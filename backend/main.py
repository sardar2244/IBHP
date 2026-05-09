from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes.scan_routes import router as scan_router
from api.routes.auth_routes import router as auth_router
import logging

# Logging Setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ibhp.log'),
        logging.StreamHandler()
    ]
)

app = FastAPI(
    title="IBHP Platform",
    description="Intelligent Bug Hunting Platform",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(
    scan_router,
    prefix="/api"
)
app.include_router(
    auth_router,
    prefix="/auth"
)

@app.get("/")
def home():
    return {
        "name": "IBHP Platform",
        "status": "Running",
        "version": "2.0.0"
    }