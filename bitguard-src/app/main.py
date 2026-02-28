from fastapi import FastAPI, Depends, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, get_db, Base, SessionLocal
from models import User, Task, Password
import schemas
from security import hash_password, verify_password
import os

# Crear tablas en la base de datos
Base.metadata.create_all(bind=engine)

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


# Crear (si no existe) un usuario por defecto al iniciar la app
@app.on_event("startup")
def ensure_default_user():
    db = SessionLocal()
    try:
        if not db.query(User).first():
            default = User(name="owner", email="owner@local", description="Cuenta principal")
            db.add(default)
            db.commit()
    finally:
        db.close()


# Endpoint para obtener el usuario por defecto (para la UI)
@app.get("/default-user")
def get_default_user(db: Session = Depends(get_db)):
    user = db.query(User).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario por defecto no encontrado")
    return {"id": user.id, "name": user.name, "email": user.email}

# Redirigir raíz a index.html (mensaje breve)
@app.get("/")
def read_root():
    return {"mensaje": "🔐 Gestor de Contraseñas - Accede a /static/index.html"}

# ======================== USUARIOS ========================
@app.post("/users/", response_model=schemas.User)
def create_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Verificar si el email ya existe
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="El email ya existe")
    
    db_user = User(**user.dict())
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Obtener todos los usuarios
@app.get("/users/", response_model=list[schemas.User])
def get_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return users

# Obtener usuario por ID
@app.get("/users/{user_id}", response_model=schemas.User)
def get_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return db_user

# Actualizar usuario
@app.put("/users/{user_id}", response_model=schemas.User)
def update_user(user_id: int, user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    for key, value in user.dict().items():
        setattr(db_user, key, value)
    
    db.commit()
    db.refresh(db_user)
    return db_user

# Eliminar usuario
@app.delete("/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Eliminar todas sus contraseñas también
    db.query(Password).filter(Password.user_id == user_id).delete()
    db.delete(db_user)
    db.commit()
    return {"mensaje": "Usuario y sus contraseñas eliminados"}

# ======================== CONTRASEÑAS ========================

# Crear contraseña
@app.post("/users/{user_id}/passwords/", response_model=schemas.PasswordResponse)
def create_password(user_id: int, password: schemas.PasswordCreate, db: Session = Depends(get_db)):
    # Verificar que el usuario existe
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    # Hashear la contraseña
    hashed_password = hash_password(password.password)
    
    # Crear registro de contraseña
    db_password = Password(
        user_id=user_id,
        title=password.title,
        username=password.username,
        password=hashed_password,
        email=password.email,
        url=password.url,
        notes=password.notes
    )
    db.add(db_password)
    db.commit()
    db.refresh(db_password)
    return db_password

# Obtener todas las contraseñas de un usuario
@app.get("/users/{user_id}/passwords/", response_model=list[schemas.PasswordResponse])
def get_user_passwords(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    
    passwords = db.query(Password).filter(Password.user_id == user_id).all()
    return passwords

# Obtener una contraseña específica
@app.get("/users/{user_id}/passwords/{password_id}", response_model=schemas.PasswordResponse)
def get_password(user_id: int, password_id: int, db: Session = Depends(get_db)):
    db_password = db.query(Password).filter(
        Password.id == password_id,
        Password.user_id == user_id
    ).first()
    if not db_password:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    return db_password

# Actualizar contraseña
@app.put("/users/{user_id}/passwords/{password_id}", response_model=schemas.PasswordResponse)
def update_password(user_id: int, password_id: int, password_data: schemas.PasswordCreate, db: Session = Depends(get_db)):
    db_password = db.query(Password).filter(
        Password.id == password_id,
        Password.user_id == user_id
    ).first()
    if not db_password:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    
    # Hashear nueva contraseña
    hashed_password = hash_password(password_data.password)
    
    db_password.title = password_data.title
    db_password.username = password_data.username
    db_password.password = hashed_password
    db_password.email = password_data.email
    db_password.url = password_data.url
    db_password.notes = password_data.notes
    
    db.commit()
    db.refresh(db_password)
    return db_password

# Verificar contraseña (para login)
@app.post("/users/{user_id}/passwords/{password_id}/verify/")
def verify_stored_password(user_id: int, password_id: int, plain_password: str, db: Session = Depends(get_db)):
    db_password = db.query(Password).filter(
        Password.id == password_id,
        Password.user_id == user_id
    ).first()
    if not db_password:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    
    is_correct = verify_password(plain_password, db_password.password)
    return {"correct": is_correct}

# Eliminar contraseña
@app.delete("/users/{user_id}/passwords/{password_id}")
def delete_password(user_id: int, password_id: int, db: Session = Depends(get_db)):
    db_password = db.query(Password).filter(
        Password.id == password_id,
        Password.user_id == user_id
    ).first()
    if not db_password:
        raise HTTPException(status_code=404, detail="Contraseña no encontrada")
    
    db.delete(db_password)
    db.commit()
    return {"mensaje": "Contraseña eliminada"}


