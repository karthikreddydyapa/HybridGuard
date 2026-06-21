# backend/config.py
from dotenv import load_dotenv
import os

load_dotenv()

HOST             = os.getenv("HOST", "127.0.0.1")
PORT             = int(os.getenv("PORT", 8000))
SERVER_URL       = os.getenv("SERVER_URL", "http://127.0.0.1:8000")
DATABASE_URL     = os.getenv("DATABASE_URL", "sqlite:///./db/hybridguard.db")
SECRET_KEY       = os.getenv("SECRET_KEY", "change-this")
JWT_ALGORITHM    = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINS  = int(os.getenv("JWT_EXPIRE_MINUTES", 480))
WATCH_PATH       = os.getenv("WATCH_PATH", "C:\\Users")