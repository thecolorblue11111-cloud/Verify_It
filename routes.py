from fastapi import APIRouter, Depends, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.status import HTTP_303_SEE_OTHER

from .models import User
from .mfa_utils import generate_totp_secret, get_totp_uri, verify_totp, generate_qr_code_base64

router = APIRouter()

def get_db():
    # Placeholder: yield your database session here
    pass

def get_current_user():
    # Placeholder: get the current user (from session/cookie/JWT)
    pass

@router.get("/mfa/setup", response_class=HTMLResponse)
async def mfa_setup(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.mfa_enabled:
        return RedirectResponse("/profile", status_code=HTTP_303_SEE_OTHER)
    secret = generate_totp_secret()
    uri = get_totp_uri(user.username, secret)
    qr_base64 = generate_qr_code_base64(uri)
    # Store secret temporarily in session or pass as hidden field (not secure, but demo)
    request.session["pending_mfa_secret"] = secret
    return templates.TemplateResponse("mfa_setup.html", {"request": request, "qr_base64": qr_base64, "secret": secret})

@router.post("/mfa/verify", response_class=HTMLResponse)
async def mfa_verify(request: Request, token: str = Form(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    secret = request.session.get("pending_mfa_secret")
    if not secret:
        raise HTTPException(status_code=400, detail="No MFA setup in progress.")
    if verify_totp(token, secret):
        user.mfa_enabled = True
        user.mfa_secret = secret
        db.add(user)
        db.commit()
        db.refresh(user)
        del request.session["pending_mfa_secret"]
        return RedirectResponse("/profile", status_code=HTTP_303_SEE_OTHER)
    else:
        return templates.TemplateResponse("mfa_verify.html", {"request": request, "error": "Invalid token"})

@router.post("/mfa/disable", response_class=HTMLResponse)
async def mfa_disable(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    user.mfa_enabled = False
    user.mfa_secret = None
    db.add(user)
    db.commit()
    db.refresh(user)
    return RedirectResponse("/profile", status_code=HTTP_303_SEE_OTHER)

# Example login route with MFA challenge
@router.post("/login", response_class=HTMLResponse)
async def login(request: Request, username: str = Form(...), password: str = Form(...), token: str = Form(None), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    if user.mfa_enabled:
        if not token:
            return templates.TemplateResponse("mfa_verify.html", {"request": request, "error": None, "mfa_required": True})
        if not verify_totp(token, user.mfa_secret):
            return templates.TemplateResponse("mfa_verify.html", {"request": request, "error": "Invalid MFA token", "mfa_required": True})
    # Set login/session logic here
    response = RedirectResponse("/dashboard", status_code=HTTP_303_SEE_OTHER)
    return response

def verify_password(plain: str, hashed: str):
    # Implement your password hashing check here
    pass
