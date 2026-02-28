from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import schemas
from security import hash_password, verify_password
from data_store import (
    list_passwords, get_password, create_password,
    update_password, delete_password
)
import os

app = FastAPI(title="Gestor de Contraseñas", version="1.0.0")

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Servir archivos estáticos
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


# Redirigir raíz a index.html (mensaje breve)
@app.get("/")
def read_root():
    return {"mensaje": "🔐 Gestor de Contraseñas - Accede a /static/index.html"}

# (Ya no usamos múltiples usuarios, el almacenamiento es JSON y solo para uno.)
# Los endpoints relacionados se eliminaron.

# ======================== CONTRASEÑAS (JSON) ========================

# Crear contraseña
@app.post("/passwords/", response_model=schemas.PasswordResponse)
def create_password_endpoint(password: schemas.PasswordCreate):
    hashed = hash_password(password.password)
    entry = password.dict()
    entry["password"] = hashed
    created = create_password(entry)
    return created

# Listar todas las contraseñas
@app.get("/passwords/", response_model=list[schemas.PasswordResponse])
def list_passwords_endpoint():
    return list_passwords()

# Obtener específica
@app.get("/passwords/{password_id}", response_model=schemas.PasswordResponse)
def get_password_endpoint(password_id: str):
    pwd = get_password(password_id)
    if not pwd:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    return pwd

# Actualizar
@app.put("/passwords/{password_id}", response_model=schemas.PasswordResponse)
def update_password_endpoint(password_id: str, password_data: schemas.PasswordCreate):
    existing = get_password(password_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    updates = password_data.dict()
    updates["password"] = hash_password(password_data.password)
    updated = update_password(password_id, updates)
    return updated

# Verificar hash
@app.post("/passwords/{password_id}/verify/")
def verify_password_endpoint(password_id: str, payload: dict):
    # payload should contain {"plain_password": "..."}
    pwd = get_password(password_id)
    if not pwd:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    plain_password = payload.get("plain_password")
    if plain_password is None:
        raise HTTPException(status_code=400, detail="plain_password required")
    return {"correct": verify_password(plain_password, pwd["password"])}

# Eliminar
@app.delete("/passwords/{password_id}")
def delete_password_endpoint(password_id: str):
    ok = delete_password(password_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    return {"mensaje": "Contraseña eliminada"}


