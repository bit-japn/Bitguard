from pydantic import BaseModel

class StoreRequest(BaseModel):
    username: str
    label: str
    encrypted_password: bytes  
    salt: bytes                
    nonce: bytes               

class RetrieveRequest(BaseModel):
    username: str
    label: str