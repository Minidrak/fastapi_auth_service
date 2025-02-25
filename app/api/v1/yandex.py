from fastapi import APIRouter, Depends, HTTPException
from app.domain.services.auth_service import AuthService
from app.utils.jwt import get_db
from app.config import config
import aiohttp

router = APIRouter(tags=["Yandex"])

@router.get("/login/yandex")
def login_yandex():
    # YANDEX_CLIENT_ID = "2dc758fef91b427ca3089117674df7f7"
    REDIRECT_URI = "http://127.0.0.1:8000/api/v1/login/yandex/callback"
    return {
        "url": f"https://oauth.yandex.ru/authorize?response_type=code&client_id={config.YANDEX_CLIENT_ID}&redirect_uri={REDIRECT_URI}"
    }

@router.get("/login/yandex/callback")
async def yandex_callback(code: str, db=Depends(get_db)):
    try:
        # YANDEX_CLIENT_ID = "2dc758fef91b427ca3089117674df7f7"
        # YANDEX_CLIENT_SECRET = "377edafb3d1949cf8bad8a9f341725c7"
        REDIRECT_URI = "http://127.0.0.1:8000/api/v1/login/yandex/callback"
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://oauth.yandex.ru/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": config.YANDEX_CLIENT_ID,
                    "client_secret": config.YANDEX_CLIENT_SECRET,
                    "redirect_uri": REDIRECT_URI
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
        
        return await AuthService.yandex_auth(email, db)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))