from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import base64

from app.database import SessionLocal, engine
from app import models

models.base.metadata.create_all(bind=engine)

from app.models import VaultEntry
from app.schemas import EntryCreate

app = FastAPI(
    title="BitGuard API",
    description="Gestor de credenciales encriptado, creado con FastAPI y MySQL.",
    version="0.3.1",
)

# CORS (#TODO: restricciones)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/vault/entries")
def create_entry(entry: EntryCreate, db: Session = Depends(get_db)):
    binary_data = base64.b64decode(entry.data)

    db_entry = VaultEntry(
        entry_id=entry.vault_id,
        vault_id=entry.entry_id,
        data=binary_data
    )

    db.add(db_entry)
    db.commit()

    return {"status": "credenciales guardadas"}

@app.get("/vault/entries/{vault_id}")
def get_entries(vault_id: str, db: Session = Depends(get_db)):
    entries = db.query(VaultEntry).filter(
        VaultEntry.vault_id == vault_id
    ).all()

    result = []

    for e in entries:
        result.append({
            "vault_id": e.vault_id,
            "entry_id": e.entry_id,
            "data": base64.b64encode(e.data).decode('utf-8')
        })
    
    return result

@app.put("/vault/entries/{entry_id}")
def update_entry(entry_id: str, entry: EntryCreate, db: Session = Depends(get_db)):
    db_entry = db.query(VaultEntry).filter(
        VaultEntry.entry_id == entry_id
    ).first()

    if not db_entry:
        raise HTTPException(status_code=404, detail="Entrada no encontrada")

    db_entry.data = base64.b64decode(entry.data)

    db.commit()

    return {"status": "credenciales actualizadas"}

@app.delete("/vault/entries/{entry_id}")
def delete_entry(entry_id: str, db: Session = Depends(get_db)):
    db_entry = db.query(VaultEntry).filter(
        VaultEntry.entry_id == entry_id
    ).first()

    if not db_entry:
        raise HTTPException(status_code=404, detail="Entrada no encontrada")

    db.delete(db_entry)
    db.commit()

    return {"status": "credenciales eliminadas"}

# Uvicorn and ping

@app.get("/ping")
def ping():
    return {"status": "running"}

import uvicorn

if __name__ == "__main__":
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8048,
        reload=False
    )