from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional
from datetime import datetime
import uuid
import json
import os
import secrets
import string
import hashlib
import requests

app = FastAPI(title="Password Manager API")

VAULT_FILE = "vault.json"


# -------------------------
# Models
# -------------------------

class Owner(BaseModel):
    user_id: str
    email: EmailStr


class Entry(BaseModel):
    entry_id: str
    service_name: str
    url: Optional[str] = None
    username: str
    password: str
    notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class EntryCreate(BaseModel):
    service_name: str
    url: Optional[str] = None
    username: str
    password: str
    notes: Optional[str] = None


class Settings(BaseModel):
    auto_lock_timeout_minutes: int = 10
    backup_enabled: bool = True


class Vault(BaseModel):
    vault_name: str
    owner: Owner
    entries: List[Entry]
    settings: Settings


# -------------------------
# Utility Functions
# -------------------------

def load_vault() -> dict:
    if not os.path.exists(VAULT_FILE):
        raise HTTPException(status_code=404, detail="Vault file not found")
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault(data: dict):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=4, default=str)


# -------------------------
# Routes
# -------------------------

@app.get("/vault", response_model=Vault)
def get_vault():
    return load_vault()


@app.get("/entries", response_model=List[Entry])
def get_entries():
    vault = load_vault()
    return vault["entries"]


@app.get("/entries/{entry_id}", response_model=Entry)
def get_entry(entry_id: str):
    vault = load_vault()
    for entry in vault["entries"]:
        if entry["entry_id"] == entry_id:
            return entry
    raise HTTPException(status_code=404, detail="Entry not found")


@app.post("/entries", response_model=Entry)
def create_entry(entry_data: EntryCreate):
    vault = load_vault()

    now = datetime.utcnow()

    new_entry = Entry(
        entry_id=str(uuid.uuid4()),
        service_name=entry_data.service_name,
        url=entry_data.url,
        username=entry_data.username,
        password=entry_data.password,
        notes=entry_data.notes,
        created_at=now,
        updated_at=now,
    )

    vault["entries"].append(new_entry.dict())
    save_vault(vault)

    return new_entry


@app.put("/entries/{entry_id}", response_model=Entry)
def update_entry(entry_id: str, entry_data: EntryCreate):
    vault = load_vault()

    for entry in vault["entries"]:
        if entry["entry_id"] == entry_id:
            entry["service_name"] = entry_data.service_name
            entry["url"] = entry_data.url
            entry["username"] = entry_data.username
            entry["password"] = entry_data.password
            entry["notes"] = entry_data.notes
            entry["updated_at"] = datetime.utcnow()
            save_vault(vault)
            return entry

    raise HTTPException(status_code=404, detail="Entry not found")


@app.delete("/entries/{entry_id}")
def delete_entry(entry_id: str):
    vault = load_vault()

    for i, entry in enumerate(vault["entries"]):
        if entry["entry_id"] == entry_id:
            vault["entries"].pop(i)
            save_vault(vault)
            return {"message": "Entry deleted"}

    raise HTTPException(status_code=404, detail="Entry not found")


# -------------------------
# Password Generator
# -------------------------

@app.get("/generate-password")
def generate_password(length: int = 16):
    if length < 8:
        raise HTTPException(status_code=400, detail="Minimum length is 8")

    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))

    return {"generated_password": password}


# -------------------------
# Password Leak Check
# -------------------------

@app.post("/check-password-leak")
def check_password_leak(password: str):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)

    if response.status_code != 200:
        raise HTTPException(status_code=500, detail="HIBP API error")

    hashes = response.text.splitlines()

    for line in hashes:
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return {
                "leaked": True,
                "times_found": int(count)
            }

    return {"leaked": False, "times_found": 0}