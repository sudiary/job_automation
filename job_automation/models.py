# models.py
from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Boolean, Text, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(150), unique=True, nullable=False)
    email = Column(String(200), unique=True, nullable=False)
    password_hash = Column(String(300), nullable=False)
    is_admin = Column(Boolean, default=False)
    profile_pic = Column(String(300), default="default.png")
    cv_file = Column(String(300), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String(128), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    user = relationship("User")

    @classmethod
    def create_token(cls, user, session, expires_minutes=30):
        token = secrets.token_urlsafe(24)
        expires = datetime.utcnow() + timedelta(minutes=expires_minutes)
        obj = cls(user_id=user.id, token=token, expires_at=expires)
        session.add(obj)
        session.commit()
        return obj

class JobListing(Base):
    __tablename__ = "job_listings"
    id = Column(Integer, primary_key=True)
    company = Column(String(200))
    position = Column(String(200))
    description = Column(Text)
    tags = Column(String(300))
    status = Column(String(50), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)

class Application(Base):
    __tablename__ = "applications"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("job_listings.id"))
    candidate_id = Column(Integer, ForeignKey("users.id"))
    stage = Column(String(80), default="applied")
    applied_at = Column(DateTime, default=datetime.utcnow)
