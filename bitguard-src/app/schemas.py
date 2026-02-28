from pydantic import BaseModel

class EntryCreate(BaseModel):
    vault_id: str
    entry_id: str
    url: str
    usr: str
    pwd: str

class EntryResponse(BaseModel):
    vault_id: str
    entry_id: str
    url: str
    usr: str
    pwd: str