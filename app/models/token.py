from app.backend.db import Base
from sqlalchemy import Column, DateTime, Integer, String


class TokenBlacklist(Base):
    __tablename__ = "token_blacklist"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True)
    expire_at = Column(DateTime(timezone=True))
