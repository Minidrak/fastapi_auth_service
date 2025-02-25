from fastapi import APIRouter, Depends, HTTPException
from app.domain.services.user_service import UserService
from app.utils.jwt import get_current_user, get_db

router = APIRouter(tags=["admin"])

@router.get("/users/{user_id}/roles")
def get_user_roles(user_id: int, current_user=Depends(get_current_user), db=Depends(get_db)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    roles = UserService.get_user_roles(user_id, db)
    if not roles:
        raise HTTPException(status_code=404, detail="User or roles not found")
    return {"user_id": user_id, "roles": roles}

@router.get("/history")
def get_auth_history(current_user=Depends(get_current_user), db=Depends(get_db)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    history = UserService.get_auth_history(db)
    return {"history": history}