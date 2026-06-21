# backend/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import Optional
import hashlib, sys, os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_MINS

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Simple SHA256 hashing (avoids bcrypt issues)
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain: str, hashed: str) -> bool:
    return hashlib.sha256(plain.encode()).hexdigest() == hashed

# Demo users
USERS = {
    "admin": {
        "username" : "admin",
        "full_name": "SOC Administrator",
        "role"     : "admin",
        "password" : hash_password("hybridguard123")
    },
    "analyst": {
        "username" : "analyst",
        "full_name": "SOC Analyst",
        "role"     : "analyst",
        "password" : hash_password("analyst123")
    }
}

class Token(BaseModel):
    access_token: str
    token_type:   str
    username:     str
    role:         str
    full_name:    str

class User(BaseModel):
    username:  str
    full_name: str
    role:      str

def authenticate_user(username: str, password: str):
    user = USERS.get(username)
    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=JWT_ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = USERS.get(username)
    if user is None:
        raise credentials_exception
    return User(
        username  = user["username"],
        full_name = user["full_name"],
        role      = user["role"]
    )

@router.post("/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    token = create_token({"sub": user["username"], "role": user["role"]})
    print(f"[AUTH] ✅ Login: {user['username']} ({user['role']})")
    return Token(
        access_token = token,
        token_type   = "bearer",
        username     = user["username"],
        role         = user["role"],
        full_name    = user["full_name"]
    )

@router.get("/me")
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.get("/verify")
async def verify_token(current_user: User = Depends(get_current_user)):
    return {"valid": True, "user": current_user}