from pydantic import BaseModel

class EntryCreate(BaseModel):
    vault_id: str
    entry_id: str
    data: str # base64 :)

class EntryResponse(BaseModel):
    vault_id: str
    entry_id: str
    data: str