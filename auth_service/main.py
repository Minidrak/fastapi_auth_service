from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import aiohttp
from kafka import KafkaProducer
import json
from models import User, LoginHistory, Role, get_db

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key")
ALGORITHM = "HS256"
YANDEX_CLIENT_ID = os.getenv("YANDEX_CLIENT_ID")
YANDEX_CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET")
REDIRECT_URI = "http://localhost:8000/auth/yandex/callback"

producer = KafkaProducer(bootstrap_servers='kafka:9092')

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def send_registration_event(user_id: int, email: str):
    event = {"user_id": user_id, "email": email}
    producer.send('registration_topic', json.dumps(event).encode('utf-8'))

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        email = payload.get("sub")
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Регистрация пользователя
@app.post("/register")
def register(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(password)
    role = db.query(Role).filter(Role.name == 'user').first()
    if not role:
        raise HTTPException(status_code=500, detail="Role 'user' not found")
    new_user = User(email=email, password=hashed_password, role_id=role.id)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    send_registration_event(new_user.id, new_user.email)
    return {"message": "User registered"}

# Вход с JWT
@app.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    login_history = LoginHistory(user_id=user.id, auth_method="JWT")
    db.add(login_history)
    db.commit()
    return {"access_token": access_token, "token_type": "bearer"}

# Вход через Yandex OAuth2
@app.get("/login/yandex")
def login_yandex():
    return {"url": f"https://oauth.yandex.ru/authorize?response_type=code&client_id={YANDEX_CLIENT_ID}&redirect_uri={REDIRECT_URI}"}

@app.get("/auth/yandex/callback")
async def yandex_callback(code: str, db: Session = Depends(get_db)):
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://oauth.yandex.ru/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": YANDEX_CLIENT_ID,
                "client_secret": YANDEX_CLIENT_SECRET,
            },
        ) as resp:
            token_data = await resp.json()
            access_token = token_data["access_token"]
        async with session.get(
            "https://login.yandex.ru/info",
            headers={"Authorization": f"OAuth {access_token}"},
        ) as resp:
            user_data = await resp.json()
            email = user_data["default_email"]
            user = db.query(User).filter(User.email == email).first()
            if not user:
                role = db.query(Role).filter(Role.name == 'user').first()
                if not role:
                    raise HTTPException(status_code=500, detail="Role 'user' not found")
                user = User(email=email, password="", role_id=role.id)
                db.add(user)
                db.commit()
                db.refresh(user)
                send_registration_event(user.id, user.email)
            access_token = create_access_token(data={"sub": user.email})
            login_history = LoginHistory(user_id=user.id, auth_method="Yandex")
            db.add(login_history)
            db.commit()
            return {"access_token": access_token, "token_type": "bearer"}

# Получение ролей пользователя
@app.get("/users/{user_id}/roles")
def get_user_roles(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role.name != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"roles": user.role.name}

# Получение истории авторизаций
@app.get("/users/{user_id}/history")
def get_login_history(user_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role.name != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    history = db.query(LoginHistory).filter(LoginHistory.user_id == user_id).all()
    return [{"login_time": h.login_time, "auth_method": h.auth_method} for h in history]