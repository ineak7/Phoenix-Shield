from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- Configuration ---
SECRET_KEY = "phoenix-shield-super-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing setup using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def hash_password(password: str) -> str:
    """Hash a plaintext password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(username: str, role: str, extra_claims: dict[str, Any] | None = None) -> str:
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


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
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
