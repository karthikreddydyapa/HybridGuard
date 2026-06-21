# backend/main.py

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from database import init_db
from routes.ingest import router as ingest_router
from routes.dashboard import router as dashboard_router
from auth import router as auth_router, get_current_user

app = FastAPI(
    title="HybridGuard",
    description="SIEM + EDR Hybrid Security Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
def startup_event():
    init_db()
    print("[HybridGuard] Server started successfully")

# Public routes
app.include_router(auth_router, prefix="/auth", tags=["Authentication"])

# Protected routes
app.include_router(
    ingest_router,
    prefix="/ingest",
    tags=["Ingestion"],
    dependencies=[Depends(get_current_user)]
)
app.include_router(
    dashboard_router,
    prefix="/dashboard",
    tags=["Dashboard"],
    dependencies=[Depends(get_current_user)]
)

@app.get("/")
def root():
    return {
        "platform" : "HybridGuard",
        "version"  : "1.0.0",
        "status"   : "running",
        "modules"  : ["SIEM", "EDR", "Correlation", "Dashboard"]
    }

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/protected-test", dependencies=[Depends(get_current_user)])
def protected_test():
    return {"message": "You are authenticated!"}