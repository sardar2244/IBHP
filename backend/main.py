from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
import sys
import os

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ibhp.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="IBHP Platform",
    description="Intelligent Bug Hunting Platform",
    version="4.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# Routes Import
try:
    from api.routes.scan_routes import router as scan_router
    app.include_router(scan_router, prefix="/api")
    logger.info("✅ Scan Routes Loaded!")
except Exception as e:
    logger.error(f"❌ Scan Routes Error: {e}")

try:
    from api.routes.auth_routes import router as auth_router
    app.include_router(auth_router, prefix="/auth")
    logger.info("✅ Auth Routes Loaded!")
except Exception as e:
    logger.error(f"❌ Auth Routes Error: {e}")

@app.get("/")
def home():
    logger.info("Home Called")
    return {
        "name": "IBHP Platform",
        "status": "Running",
        "version": "4.0.0"
    }

@app.get("/health")
def health():
    return {
        "status": "OK",
        "message": "Server Running!"
    }