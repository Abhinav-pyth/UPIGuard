"""
main.py - UPIGuard FastAPI backend.

Routes
---
GET  /api/health          - liveness + DB stats
POST /api/register        - create account (requires consent)
POST /api/otp/request     - send / return OTP for email
POST /api/otp/verify      - verify OTP -> issue JWT
POST /api/login           - email+password login -> JWT
POST /api/check           - breach check (requires Bearer JWT)
GET  /api/dashboard       - user's own check history (requires Bearer JWT)
---
"""

import json
import os
import random
import re
import time
from pathlib import Path
from datetime import datetime, timezone
import sys

# Add current directory to sys.path for Vercel / local imports
current_dir = Path(__file__).parent
if str(current_dir) not in sys.path:
    sys.path.append(str(current_dir))

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import auth
import db
import admin_log

load_dotenv()

OTP_IN_RESPONSE: bool = os.getenv("OTP_IN_RESPONSE", "true").lower() == "true"
OTP_EXPIRE_SECONDS: int = int(os.getenv("OTP_EXPIRE_SECONDS", "300"))

# -- Rate Limiter --

limiter = Limiter(key_func=get_remote_address)

# -- App --

app = FastAPI(
    title="UPIGuard API",
    description="Secure UPI breach checker with auth, OTP, and admin logging.",
    version="2.0.0",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)

# -- In-memory OTP store: { email -> (code, expires_at) } --

_otp_store: dict[str, tuple[str, float]] = {}

def _generate_otp(email: str) -> str:
    code = str(random.randint(100000, 999999))
    _otp_store[email.lower()] = (code, time.time() + OTP_EXPIRE_SECONDS)
    return code

def _verify_otp(email: str, code: str) -> bool:
    entry = _otp_store.get(email.lower())
    if not entry:
        return False
    stored_code, expires_at = entry
    if time.time() > expires_at:
        _otp_store.pop(email.lower(), None)
        return False
    if stored_code != code.strip():
        return False
    _otp_store.pop(email.lower(), None)   # one-time use
    return True

# -- Auth dependency --

_bearer = HTTPBearer(auto_error=False)

def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> dict:
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated.")
    payload = auth.decode_token(creds.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token.")
    user = db.get_user_by_id(payload.get("sub", ""))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")
    return user

# -- Data Loading --

DATA_PATH = Path(__file__).parent / "data" / "breaches.json"

def load_breach_db() -> dict[str, list[dict]]:
    with open(DATA_PATH, "r", encoding="utf-8") as f:
        raw = json.load(f)
    index: dict[str, list[dict]] = {}
    for record in raw["breaches"]:
        key = record["upi_id"].strip().lower()
        index.setdefault(key, []).append(record)
    return index

BREACH_INDEX = load_breach_db()

# -- Schemas --

UPI_PATTERN = re.compile(r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$")

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str
    consent_given: bool

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters.")
        return v

    @field_validator("consent_given")
    @classmethod
    def must_consent(cls, v: bool) -> bool:
        if not v:
            raise ValueError("You must accept the terms to register.")
        return v

class OTPRequestBody(BaseModel):
    email: EmailStr

class OTPVerifyBody(BaseModel):
    email: EmailStr
    code: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class CheckRequest(BaseModel):
    upi_id: str

    @field_validator("upi_id")
    @classmethod
    def validate_upi(cls, v: str) -> str:
        v = v.strip()
        if not UPI_PATTERN.match(v):
            raise ValueError(
                "Invalid UPI ID format. Expected: username@bankhandle (e.g. john@oksbi)"
            )
        return v

class BreachRecord(BaseModel):
    breach_date: str
    source: str
    severity: str
    records_exposed: list[str]
    description: str

class CheckResponse(BaseModel):
    upi_id: str
    is_compromised: bool
    breach_count: int
    breaches: list[BreachRecord]
    checked_at: str
    message: str

# -- Helpers --

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}

def sort_breaches(breaches: list[dict]) -> list[dict]:
    return sorted(
        breaches,
        key=lambda b: (SEVERITY_ORDER.get(b["severity"], 0), b["breach_date"]),
        reverse=True,
    )

def client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

# -- Routes - Public --

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "breach_records_loaded": sum(len(v) for v in BREACH_INDEX.values()),
        "unique_upi_ids_in_db": len(BREACH_INDEX),
    }


@app.post("/api/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, body: RegisterRequest):
    if db.get_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    hashed_pw = auth.hash_password(body.password)
    user = db.create_user(
        email=body.email,
        hashed_password=hashed_pw,
        consent_given=body.consent_given,
    )
    return {"message": "Account created. Please verify your email with an OTP.", "user_id": user["id"]}


@app.post("/api/otp/request")
@limiter.limit("5/minute")
def otp_request(request: Request, body: OTPRequestBody):
    user = db.get_user_by_email(body.email)
    if not user:
        # Don't reveal whether the email exists (OWASP A07)
        return {"message": "If that email is registered, an OTP has been sent."}
    code = _generate_otp(body.email)
    # In dev: print to terminal + optionally return in response
    print(f"\n[OTP] for {body.email}: {code}  (expires in {OTP_EXPIRE_SECONDS}s)\n")
    response: dict = {"message": "OTP sent. Check your terminal (dev mode)."}
    if OTP_IN_RESPONSE:
        response["otp_dev"] = code   # Remove in production
    return response


@app.post("/api/otp/verify")
@limiter.limit("10/minute")
def otp_verify(request: Request, body: OTPVerifyBody):
    user = db.get_user_by_email(body.email)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid OTP or email.")
    if not _verify_otp(body.email, body.code):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP.")
    db.mark_otp_verified(user["id"])
    token = auth.create_access_token({"sub": user["id"], "email": user["email"]})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/api/login")
@limiter.limit("10/minute")
def login(request: Request, body: LoginRequest):
    user = db.get_user_by_email(body.email)
    # Constant-time comparison to prevent timing attacks (OWASP A02)
    if not user or not auth.verify_password(body.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    token = auth.create_access_token({"sub": user["id"], "email": user["email"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "otp_verified": user.get("otp_verified", False),
    }


# -- Routes - Protected --

@app.post("/api/check", response_model=CheckResponse)
@limiter.limit("10/minute")
def check_upi(
    request: Request,
    payload: CheckRequest,
    current_user: dict = Depends(get_current_user),
):
    upi_id = payload.upi_id.strip()
    key = upi_id.lower()
    matches = BREACH_INDEX.get(key, [])
    sorted_matches = sort_breaches(matches)

    message = (
        f"ALERT: Your UPI ID was found in {len(matches)} breach(es). Immediate action recommended."
        if matches else
        "SAFE: Your UPI ID was not found in our breach database. Stay vigilant."
    )

    upi_hash   = auth.hash_upi_id(upi_id)
    upi_masked = db.mask_upi(upi_id)

    # Save hashed record to user's history
    db.save_check(
        user_id=current_user["id"],
        upi_hash=upi_hash,
        upi_masked=upi_masked,
        is_compromised=bool(matches),
        breach_count=len(matches),
    )

    # Log plaintext to admin-only spreadsheet (filesystem, no API exposure)
    try:
        admin_log.log_check(
            user_email=current_user["email"],
            upi_id_plaintext=upi_id,
            upi_hash=upi_hash,
            is_compromised=bool(matches),
            breach_count=len(matches),
            client_ip=client_ip(request),
        )
    except Exception as exc:
        # Don't fail the request if logging fails — log error server-side
        print(f"[admin_log] Error writing spreadsheet: {exc}")

    return CheckResponse(
        upi_id=upi_id,
        is_compromised=bool(matches),
        breach_count=len(matches),
        breaches=[BreachRecord(**b) for b in sorted_matches],
        checked_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        message=message,
    )


@app.get("/api/dashboard")
def dashboard(current_user: dict = Depends(get_current_user)):
    checks = db.get_checks_for_user(current_user["id"])
    return {
        "email": current_user["email"],
        "otp_verified": current_user.get("otp_verified", False),
        "member_since": current_user.get("created_at", ""),
        "total_checks": len(checks),
        "checks": checks,
    }


# -- Serve Frontend --

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"

if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(FRONTEND_DIR / "index.html")
