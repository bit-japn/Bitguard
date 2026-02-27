from sqlalchemy import Column, Integer, String, LargeBinary
from .database import Base

class PasswordEntry(Base):
    __tablename__ = "passwords"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, index=True)
    label = Column(String, index=True)
    encrypted_password = Column(LargeBinary)
    salt = Column(LargeBinary)
    nonce = Column(LargeBinary)