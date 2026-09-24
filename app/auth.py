import os
import hashlib
import secrets
import hmac
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================
SECRET_KEY = "phoenix-shield-super-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

PASSWORD_SALT_SIZE = 16
PASSWORD_HASH_SIZE = 32
SESSION_TOKEN_SIZE = 32

# Fallback passlib context for legacy bcrypt hashes
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/private/login", auto_error=False)


# ============================================================
# PASSWORD HASHING (SCRYPT + BCRYPT / PLAINTEXT COMPATIBILITY)
# ============================================================
def hash_password(password: str) -> str:
    """
    Securely hash a password using scrypt (Member 2 specification).
    Stored format: scrypt$salt$hash
    """
    salt = os.urandom(PASSWORD_SALT_SIZE)
    password_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=PASSWORD_HASH_SIZE
    )
    return f"scrypt${salt.hex()}${password_hash.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """
    Verify a password against stored hash:
    1. Supports scrypt (scrypt$salt$hash)
    2. Supports bcrypt ($2b$ or $2a$)
    3. Supports plaintext match for backward compatibility with legacy demo entries
    """
    if not stored_hash or not plain_password:
        return False

    # Check for scrypt format
    if stored_hash.startswith("scrypt$"):
        try:
            parts = stored_hash.split("$")
            if len(parts) == 3:
                _, salt_hex, hash_hex = parts
                salt = bytes.fromhex(salt_hex)
                expected_hash = bytes.fromhex(hash_hex)
                actual_hash = hashlib.scrypt(
                    plain_password.encode("utf-8"),
                    salt=salt,
                    n=2**14,
                    r=8,
                    p=1,
                    dklen=PASSWORD_HASH_SIZE
                )
                return hmac.compare_digest(actual_hash, expected_hash)
        except Exception:
            return False

    # Check for bcrypt format
    if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return pwd_context.verify(plain_password, stored_hash)
        except Exception:
            return False

    # Fallback: Plaintext match (legacy dev accounts)
    return hmac.compare_digest(plain_password, stored_hash)


# ============================================================
# SESSION MANAGEMENT (COOKIE-BASED, MEMBER 2 SPECIFICATION)
# ============================================================
def create_session(db_file: str, username: str) -> str:
    """
    Create a secure random session token.
    Only the SHA-256 hash of the token is stored in the database.
    """
    session_token = secrets.token_urlsafe(SESSION_TOKEN_SIZE)
    token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()

    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO sessions (token_hash, username)
        VALUES (?, ?)
        """,
        (token_hash, username)
    )
    conn.commit()
    conn.close()
    return session_token


def get_current_user_from_session(request: Request, db_file: str) -> str | None:
    """
    Get the username associated with the current session token stored in cookies.
    """
    session_token = request.cookies.get("phoenix_session")
    if not session_token:
        return None

    token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT username FROM sessions
        WHERE token_hash = ?
        """,
        (token_hash,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None
    return row[0]


def require_user(request: Request, db_file: str) -> str:
    """
    Require an authenticated user from session cookie or Bearer token.
    Raises HTTP 401 if unauthorized.
    """
    username = get_current_user_from_session(request, db_file)
    if username:
        return username

    # Check Authorization header as fallback
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1]
        payload = decode_access_token(token)
        if payload and payload.get("sub"):
            return payload.get("sub")

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required."
    )


def delete_session(request: Request, db_file: str) -> None:
    """
    Delete the active session token from the database.
    """
    session_token = request.cookies.get("phoenix_session")
    if not session_token:
        return

    token_hash = hashlib.sha256(session_token.encode("utf-8")).hexdigest()
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
    conn.commit()
    conn.close()


# ============================================================
# JWT TOKEN MANAGEMENT (MEMBER 1 SPECIFICATION)
# ============================================================
def create_access_token(username: str, role: str = "private_user", extra_claims: dict[str, Any] | None = None) -> str:
    """Create a signed JWT token containing identity and role information."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode: dict[str, Any] = {"sub": username, "role": role, "exp": expire}
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    """Decode and validate a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user(token: str | None = Depends(oauth2_scheme)) -> dict:
    """FastAPI dependency that validates a JWT token."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token is missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    username = payload.get("sub")
    role = payload.get("role")
    if username is None or role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is invalid.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {"username": username, "role": role, "token": token, "payload": payload}


def require_role(*allowed_roles: str):
    """FastAPI dependency that restricts access to specific user roles."""
    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource.",
            )
        return current_user
    return role_checker


# --- Permissions Mapping ---
PERMISSIONS = {
    "private_user": {"read", "write"},
    "staff": {"read", "write", "view_logs"},
    "mnc_admin": {"read", "write", "delete", "view_logs", "trigger_lockdown", "manage_software_upgrade"},
    "admin": {"read", "write", "delete", "view_logs", "trigger_lockdown"},
}


def is_allowed(role: str, action: str) -> bool:
    """Checks if a given user role is permitted to perform a specific action."""
    return action in PERMISSIONS.get(role, set())