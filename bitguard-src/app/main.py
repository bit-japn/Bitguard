from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from .database import SessionLocal, engine
from . import models, schemas

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Zero-Knowledge Password Manager API")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/store")
def store(req: schemas.StoreRequest, db: Session = Depends(get_db)):
    entry = models.PasswordEntry(
        username=req.username,
        label=req.label,
        encrypted_password=req.encrypted_password,
        salt=req.salt,
        nonce=req.nonce
    )
    db.add(entry)
    db.commit()
    return {"status": "stored securely"}

@app.post("/retrieve")
def retrieve(req: schemas.RetrieveRequest, db: Session = Depends(get_db)):
    entry = db.query(models.PasswordEntry).filter_by(
        username=req.username,
        label=req.label
    ).first()

    if not entry:
        raise HTTPException(status_code=404, detail="Not found")

    # Return encrypted blob — client decrypts locally
    return {
        "encrypted_password": entry.encrypted_password,
        "salt": entry.salt,
        "nonce": entry.nonce
    }