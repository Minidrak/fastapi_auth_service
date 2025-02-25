from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.domain.models.user import Base

engine = create_engine('postgresql://user:password@db:5432/dbname')
Base.metadata.create_all(engine)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
