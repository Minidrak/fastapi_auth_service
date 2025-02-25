from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.domain.models.base import Base
from app.domain.models.role import Role

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=True)
    role_id = Column(Integer, ForeignKey('roles.id'))
    created_at = Column(DateTime, default=datetime.now)
    role = relationship(Role)
