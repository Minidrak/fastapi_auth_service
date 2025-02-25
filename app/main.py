from fastapi import FastAPI
from app.api.v1.auth import router as auth_router
from app.api.v1.admin import router as admin_router
from app.api.v1.yandex import router as yandex_router

app = FastAPI(
    title="Auth API",
    description="",
    version="1.0.0",
    openapi_tags=[
        {"name": "Local"},
        {"name": "Yandex"},
        {"name": "admin"}
    ]
)

app.include_router(auth_router, prefix="/api/v1/auth")
app.include_router(admin_router, prefix="/api/v1/admin")
app.include_router(yandex_router, prefix="/api/v1")