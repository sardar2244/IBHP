from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import sys

load_dotenv()

router = APIRouter()

pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

SECRET_KEY = os.getenv(
    'SECRET_KEY', 'ibhp-secret-key-2026'
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
    expire = datetime.utcnow() + timedelta(hours=24)
    data = {
        "sub": username,
        "exp": expire
    }
    return jwt.encode(data, SECRET_KEY, ALGORITHM)


# ==================
# REGISTER
# ==================
@router.post("/register")
def register(user: UserRegister):
    try:
        BASE = os.path.dirname(__file__)
        sys.path.append(
            os.path.abspath(
                os.path.join(BASE, '..', '..')
            )
        )
        from models.database import db

        # Validation
        if len(user.username) < 3:
            raise HTTPException(
                status_code=400,
                detail="Username 3+ characters chahiye"
            )

        if len(user.password) < 4:
            raise HTTPException(
                status_code=400,
                detail="Password 4+ characters chahiye"
            )

        # Check Exists
        existing = db.get_user(user.username)
        if existing:
            raise HTTPException(
                status_code=400,
                detail="Username Already Exists!"
            )

        # Hash Password
        hashed = pwd_context.hash(user.password)

        # Save
        user_data = {
            'username': user.username,
            'email': user.email,
            'password': hashed,
            'role': 'user',
            'created_at': datetime.utcnow().isoformat()
        }
        db.save_user(user_data)

        # Auto Login
        token = create_token(user.username)

        return {
            "status": "success",
            "message": "Registration Successful!",
            "token": token,
            "username": user.username
        }
    except HTTPException:
        raise
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }


# ==================
# LOGIN
# ==================
@router.post("/login")
def login(user: UserLogin):
    try:
        BASE = os.path.dirname(__file__)
        sys.path.append(
            os.path.abspath(
                os.path.join(BASE, '..', '..')
            )
        )
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

        # Token
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


# ==================
# GET USERS
# ==================
@router.get("/users")
def get_users():
    try:
        BASE = os.path.dirname(__file__)
        sys.path.append(
            os.path.abspath(
                os.path.join(BASE, '..', '..')
            )
        )
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


# ==================
# GET PROFILE
# ==================
@router.get("/profile/{username}")
def get_profile(username: str):
    try:
        BASE = os.path.dirname(__file__)
        sys.path.append(
            os.path.abspath(
                os.path.join(BASE, '..', '..')
            )
        )
        from models.database import db
        user = db.get_user(username)
        if not user:
            return {
                "status": "error",
                "message": "User Not Found!"
            }
        # Password Hide Karo
        user.pop('password', None)
        return {
            "status": "success",
            "user": user
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }