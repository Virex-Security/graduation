from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel
from app.db.session import get_db
from app.db.models import User, AuditLog
from app.auth.utils import verify_password, create_access_token, get_password_hash

router = APIRouter()

class LoginRequest(BaseModel):
    username: str
    password: str

@router.post("/login")
def login(login_data: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()
    
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Mint JWT
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    
    # HttpOnly Cookie (prevents XSS cookie theft)
    response.set_cookie(
        key="auth_token",
        value=access_token,
        httponly=True,
        secure=True,  # In prod, this ensures it's only sent over HTTPS
        samesite="lax",
        max_age=8 * 3600
    )

    # Audit Logging
    client_ip = request.client.host if request.client else "Unknown"
    audit = AuditLog(user_id=user.id, action="Login", ip_address=client_ip)
    db.add(audit)
    db.commit()

    return {"message": "Login successful"}

@router.post("/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    # Clear the HttpOnly cookie
    response.delete_cookie("auth_token")
    
    # Generic logout log
    client_ip = request.client.host if request.client else "Unknown"
    audit = AuditLog(user_id=0, action="Logout", ip_address=client_ip)
    db.add(audit)
    db.commit()
    return {"message": "Logout successful"}
