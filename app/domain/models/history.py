from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.domain.models.base import Base
from app.domain.models.user import User

class LoginHistory(Base):
    __tablename__ = 'auth_history'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    login_time = Column(DateTime, default=datetime.utcnow)
    auth_method = Column(String)
    user = relationship(User)
