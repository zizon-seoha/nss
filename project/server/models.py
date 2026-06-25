from sqlalchemy import Boolean, Column, Integer, String

from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    # Admin must flip this to True before the user can log in.
    is_allowed = Column(Boolean, default=False, nullable=False)
    # Permanent key shown after the first successful web login.
    # main.py sends this key to /verify-key to unlock the webcam.
    api_key = Column(String, unique=True, index=True, nullable=True)
