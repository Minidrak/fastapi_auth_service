from app.domain.models.user import User
from app.domain.models.role import Role
from app.domain.models.history import LoginHistory

class UserService:
    @staticmethod
    def get_user_roles(user_id: int, db):
        user = db.query(User).join(Role).filter(User.id == user_id).first()
        if not user:
            return None
        return user.role.name

    @staticmethod
    def get_auth_history(db):
        history = db.query(LoginHistory).all()
        return [{"user_id": h.user_id, "login_time": h.login_time, "auth_method": h.auth_method} for h in history]