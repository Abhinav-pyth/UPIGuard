"""
db.py — Lightweight JSON-file persistence for users and check history.

Files:
  backend/data/users.json   — registered accounts
  backend/data/checks.json  — per-user check history (hashed UPI IDs only)
"""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Paths ─────────────────────────────────────────────────────────────────────

_DATA_DIR   = Path(__file__).parent / "data"
_USERS_PATH  = _DATA_DIR / "users.json"
_CHECKS_PATH = _DATA_DIR / "checks.json"

# ── Low-level helpers ─────────────────────────────────────────────────────────

def _read(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def _write(path: Path, data: dict) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except OSError as e:
        # On Vercel (read-only filesystem), this will fail.
        # We log it and continue so the user request doesn't crash.
        print(f"[DB] Warning: Could not write to {path} (likely read-only FS): {e}")

# ── Users ─────────────────────────────────────────────────────────────────────

def get_user_by_email(email: str) -> dict | None:
    db = _read(_USERS_PATH)
    for u in db.get("users", []):
        if u["email"].lower() == email.lower():
            return u
    return None

def get_user_by_id(user_id: str) -> dict | None:
    db = _read(_USERS_PATH)
    for u in db.get("users", []):
        if u["id"] == user_id:
            return u
    return None

def create_user(email: str, hashed_password: str, consent_given: bool) -> dict:
    db = _read(_USERS_PATH)
    users: list = db.get("users", [])
    user = {
        "id":              str(uuid.uuid4()),
        "email":           email.lower().strip(),
        "hashed_password": hashed_password,
        "consent_given":   consent_given,
        "created_at":      datetime.now(timezone.utc).isoformat(),
        "otp_verified":    True,
    }
    users.append(user)
    _write(_USERS_PATH, {"users": users})
    return user


# ── Check History ─────────────────────────────────────────────────────────────

def save_check(
    *,
    user_id: str,
    upi_hash: str,
    upi_masked: str,
    is_compromised: bool,
    breach_count: int,
) -> dict:
    """Save a check record. Only the hash of the UPI ID is stored."""
    db = _read(_CHECKS_PATH)
    checks: list = db.get("checks", [])
    record = {
        "id":             str(uuid.uuid4()),
        "user_id":        user_id,
        "upi_hash":       upi_hash,
        "upi_masked":     upi_masked,   # e.g. "r***l@oksbi"  — safe to display
        "is_compromised": is_compromised,
        "breach_count":   breach_count,
        "checked_at":     datetime.now(timezone.utc).isoformat(),
    }
    checks.append(record)
    _write(_CHECKS_PATH, {"checks": checks})
    return record

def get_checks_for_user(user_id: str, limit: int = 20) -> list[dict]:
    """Return the most recent `limit` checks for a user."""
    db = _read(_CHECKS_PATH)
    user_checks = [c for c in db.get("checks", []) if c["user_id"] == user_id]
    return sorted(user_checks, key=lambda c: c["checked_at"], reverse=True)[:limit]


# ── UPI masking helper ────────────────────────────────────────────────────────

def mask_upi(upi_id: str) -> str:
    """Turn 'rahul@oksbi' → 'r***l@oksbi' for safe display."""
    try:
        local, handle = upi_id.split("@", 1)
        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{handle}"
    except ValueError:
        return "****@****"
