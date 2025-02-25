from sqlalchemy import Column, Integer, String
from app.domain.models.base import Base

class Role(Base):
    __tablename__ = 'roles'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
