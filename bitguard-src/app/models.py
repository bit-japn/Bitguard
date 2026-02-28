from sqlalchemy import Column, String, LargeBinary, DateTime
from sqlalchemy.sql import func
from sqlalchemy.orm import declarative_base

base = declarative_base()

class VaultEntry(base):
    __tablename__ = "vaults"

    vault_id = Column(String(36), index=True, nullable=False)
    entry_id = Column(String(36), primary_key=True, index=True)
    data = Column(LargeBinary, nullable=False)

    created_at = Column(DateTime(timezone=True),
                        server_default=func.now())
    updated_at = Column(DateTime(timezone=True),
                        server_default=func.now(),
                        onupdate=func.now())