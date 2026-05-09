from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()

router = APIRouter()

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

SECRET_KEY = os.getenv(
    'SECRET_KEY',
    'ibhp-secret-key-2026'
)
ALGORITHM = "HS256"

class UserRegister(BaseModel):
    username: str
    password: str
    email: str

class UserLogin(BaseModel):
    username: str
    password: str

def create_token(username: str):
    expire = datetime.utcnow() + \
        timedelta(hours=24)
    data = {
        "sub": username,
        "exp": expire
    }
    return jwt.encode(
        data, SECRET_KEY, ALGORITHM
    )

@router.post("/register")
def register(user: UserRegister):
    try:
        from models.database import db
        
        # Check User Exists
        existing = db.get_user(user.username)
        if existing:
            raise HTTPException(
                status_code=400,
                detail="User Already Exists!"
            )
        
        # Hash Password
        hashed = pwd_context.hash(user.password)
        
        # Save User
        user_data = {
            'username': user.username,
            'email': user.email,
            'password': hashed,
            'role': 'user',
            'created_at': datetime.utcnow().isoformat()
        }
        db.save_user(user_data)
        
        return {
            "status": "success",
            "message": "Registration Successful!"
        }
    except HTTPException:
        raise
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@router.post("/login")
def login(user: UserLogin):
    try:
        from models.database import db
        
        # Get User
        db_user = db.get_user(user.username)
        if not db_user:
            raise HTTPException(
                status_code=401,
                detail="User Not Found!"
            )
        
        # Verify Password
        if not pwd_context.verify(
            user.password,
            db_user['password']
        ):
            raise HTTPException(
                status_code=401,
                detail="Wrong Password!"
            )
        
        # Create Token
        token = create_token(user.username)
        
        return {
            "status": "success",
            "token": token,
            "username": user.username,
            "message": "Login Successful!"
        }
    except HTTPException:
        raise
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@router.get("/users")
def get_users():
    try:
        from models.database import db
        users = db.get_all_users()
        return {
            "status": "success",
            "users": users,
            "total": len(users)
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }