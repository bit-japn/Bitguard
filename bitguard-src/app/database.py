from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Crear conexión a la base de datos SQLite
DATABASE_URL = "sqlite:///./test.db"

engine = create_engine(
    DATABASE_URL, 
    connect_args={"check_same_thread": False}  # Solo para SQLite
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependencia para obtener la sesión de BD en cada request
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
