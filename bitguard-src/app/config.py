import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
PASSWORD_LENGTH = int(os.getenv("PASSWORD_LENGTH", 24))

ARGON2_TIME_COST = int(os.getenv("ARGON2_TIME_COST", 3))
ARGON2_MEMORY_COST = int(os.getenv("ARGON2_MEMORY_COST", 65536))
ARGON2_PARALLELISM = int(os.getenv("ARGON2_PARALLELISM", 4))

SECRET_KEY = os.getenv("SECRET_KEY")