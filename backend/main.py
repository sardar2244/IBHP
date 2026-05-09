from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routes.scan_routes import router

app = FastAPI(
    title="IBHP Platform",
    description="Intelligent Bug Hunting Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

app.include_router(
    router, 
    prefix="/api"
)

@app.get("/")
def home():
    return {
        "name": "IBHP Platform",
        "status": "Running",
        "version": "1.0.0"
    }