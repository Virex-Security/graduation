from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.auth.routes import router as auth_router
from app.db.session import engine, Base

# Initialize Database Schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Virex Secure Edge API", 
    version="2.0.0",
    description="Production-grade backend with integrated Identity Provider and WAF Engine."
)

# CORS Configuration (Restrict to frontend domain in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Identity Provider Routes
app.include_router(auth_router, prefix="/api/auth", tags=["Centralized Authentication"])

@app.get("/api/health")
def health_check():
    """Simple health check endpoint."""
    return {"status": "Fortified API is online and healthy."}
