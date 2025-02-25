from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from app.domain.services.auth_service import AuthService
from app.utils.jwt import get_current_user, get_db
from app.domain.models.user import User, Role

router = APIRouter(tags=["Local"])

@router.post("/register")
def register(email: str, password: str, db=Depends(get_db)):
    try:
        return AuthService.register_user(email, password, db)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    try:
        return AuthService.login_user(form_data.username, form_data.password, db)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))