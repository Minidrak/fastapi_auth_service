from app.domain.models.user import User
from app.domain.models.role import Role
from app.utils.jwt import create_access_token, get_password_hash, verify_password
from kafka import KafkaProducer
import json

producer = KafkaProducer(bootstrap_servers='kafka:9092')

class AuthService:
    @staticmethod
    def register_user(email: str, password: str, db):
        if not email or not password:
            raise Exception("Email and password are required")
        user = db.query(User).filter(User.email == email).first()
        if user:
            raise Exception("Email already registered")
        hashed_password = get_password_hash(password)
        role = db.query(Role).filter(Role.name == 'user').first()
        if not role:
            raise Exception("Role 'user' not found")
        new_user = User(email=email, password=hashed_password, role_id=role.id)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        AuthService._send_registration_event(new_user.id, new_user.email)
        return {"message": "User registered"}

    @staticmethod
    def login_user(email: str, password: str, db):
        user = db.query(User).filter(User.email == email).first()
        if not user or not verify_password(password, user.password):
            raise Exception("Incorrect email or password")
        access_token = create_access_token({"sub": user.email, "role": "user"})
        from app.domain.models.history import LoginHistory
        login_history = LoginHistory(user_id=user.id, auth_method="JWT")
        db.add(login_history)
        db.commit()
        return {"access_token": access_token, "token_type": "bearer"}

    @staticmethod
    async def yandex_auth(email: str, db):
        user = db.query(User).filter(User.email == email).first()
        if not user:
            role = db.query(Role).filter(Role.name == 'user').first()
            if not role:
                raise Exception("Role 'user' not found")
            user = User(email=email, password="", role_id=role.id)
            db.add(user)
            db.commit()
            db.refresh(user)
            AuthService._send_registration_event(user.id, user.email)
        access_token = create_access_token({"sub": user.email, "role": "user"})
        from app.domain.models.history import LoginHistory
        login_history = LoginHistory(user_id=user.id, auth_method="Yandex")
        db.add(login_history)
        db.commit()
        return {"access_token": access_token, "token_type": "bearer"}

    @staticmethod
    def _send_registration_event(user_id: int, email: str):
        event = {"user_id": user_id, "email": email}
        producer.send('registration_topic', json.dumps(event).encode('utf-8'))