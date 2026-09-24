from fastapi import (
    FastAPI,
    Request,
    Response,
    HTTPException,
    UploadFile,
    File,
    Form,
    Header,
    Depends,
    status
)
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel
import shutil
import os
import sys
import sqlite3
import mimetypes
import time
import uuid
import json

# ---------------------------------------------------------
# IMPORT INTERNAL MODULES (MEMBER 1 & MEMBER 2)
# ---------------------------------------------------------
from app.auth import (
    hash_password,
    verify_password,
    create_session,
    get_current_user_from_session,
    require_user,
    delete_session,
    create_access_token,
    decode_access_token,
    get_current_user,
    require_role,
    is_allowed
)

from app.canary_token import (
    initialize_canary,
    get_canary_info,
    trigger_canary,
    get_canary_events,
    CANARY_FILE,
    CANARY_ID
)

from app.encryption.encryption import (
    generate_key,
    encrypt_file_data,
    decrypt_file_data
)

from app.encryption.key_manager import LocalKeyManager
from app.anomaly_detection import detect_payload_anomaly, analyze_file_anomaly

# ---------------------------------------------------------
# FASTAPI APPLICATION INITIALIZATION
# ---------------------------------------------------------
app = FastAPI(
    title="Phoenix Shield API",
    description="Unified Cyber Protection & Enterprise Gateway - AES-256-GCM, Canary Tokens & Threat IDS",
    version="5.0.0"
)

# ---------------------------------------------------------
# DIRECTORIES & STORAGE SETUP
# ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_STORAGE_DIR = os.path.join(BASE_DIR, "encrypted_storage")
KEY_STORAGE_DIR = os.path.join(BASE_DIR, "key_storage")
METADATA_DIR = os.path.join(BASE_DIR, "metadata")
TEMPORARY_DIR = os.path.join(BASE_DIR, "temporary")
CANARY_DIR = os.path.join(BASE_DIR, "canary")
DB_FILE = os.path.join(BASE_DIR, "users.db")

for path in [UPLOAD_DIR, ENCRYPTED_STORAGE_DIR, KEY_STORAGE_DIR, METADATA_DIR, TEMPORARY_DIR, CANARY_DIR]:
    os.makedirs(path, exist_ok=True)

# ---------------------------------------------------------
# LOCAL KEY MANAGER
# ---------------------------------------------------------
key_manager = LocalKeyManager(KEY_STORAGE_DIR)

# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------
def init_db():
    initialize_canary()

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Core user & session management
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY, 
                        password TEXT,
                        email TEXT,
                        phone TEXT,
                        dob TEXT,
                        is_verified INTEGER DEFAULT 0
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        token_hash TEXT UNIQUE NOT NULL,
                        username TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS folders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        name TEXT, 
                        username TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_id TEXT,
                        filename TEXT,
                        username TEXT,
                        folder_name TEXT,
                        file_type TEXT,
                        size_str TEXT,
                        encrypted_path TEXT,
                        is_encrypted INTEGER DEFAULT 1
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS trash_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_id TEXT,
                        filename TEXT,
                        username TEXT,
                        size_str TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS traffic_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        ip_address TEXT, 
                        endpoint TEXT, 
                        method TEXT, 
                        status TEXT, 
                        threat_level TEXT, 
                        timestamp REAL
                    )''')

    # Enterprise Module Data Tables
    cursor.execute('''CREATE TABLE IF NOT EXISTS employees (
                        employee_id TEXT PRIMARY KEY,
                        name TEXT,
                        department TEXT,
                        role TEXT,
                        email TEXT,
                        password TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS attendance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        work_date TEXT,
                        check_in TEXT,
                        check_out TEXT,
                        status TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS leave_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        leave_type TEXT,
                        start_date TEXT,
                        end_date TEXT,
                        reason TEXT,
                        status TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT,
                        description TEXT,
                        assigned_to TEXT,
                        priority TEXT,
                        due_date TEXT,
                        status TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS projects (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        description TEXT,
                        progress INTEGER
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        sender_employee_id TEXT,
                        message TEXT,
                        created_at REAL
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS announcements (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT,
                        message TEXT,
                        created_at REAL
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS meetings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        title TEXT,
                        meeting_date TEXT,
                        meeting_time TEXT,
                        description TEXT,
                        organizer_employee_id TEXT,
                        status TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS payroll (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        month TEXT,
                        basic REAL,
                        allowances REAL,
                        deductions REAL,
                        net REAL,
                        status TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS documents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        filename TEXT,
                        category TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS training (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        title TEXT,
                        description TEXT,
                        progress INTEGER,
                        status TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS kpi (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        title TEXT,
                        target TEXT,
                        progress INTEGER,
                        review_note TEXT
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS support_tickets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ticket_no TEXT,
                        employee_id TEXT,
                        category TEXT,
                        subject TEXT,
                        description TEXT,
                        priority TEXT,
                        status TEXT,
                        created_at REAL
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        action TEXT,
                        entity TEXT,
                        details TEXT,
                        created_at REAL
                    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS notifications (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        employee_id TEXT,
                        title TEXT,
                        message TEXT,
                        is_read INTEGER DEFAULT 0
                    )''')

    # Auto-migrate existing tables if columns are missing
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [c[1] for c in cursor.fetchall()]
    for col, col_def in [("email", "TEXT"), ("phone", "TEXT"), ("dob", "TEXT"), ("is_verified", "INTEGER DEFAULT 0")]:
        if col not in user_cols:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col} {col_def}")

    cursor.execute("PRAGMA table_info(files)")
    file_cols = [c[1] for c in cursor.fetchall()]
    for col, col_def in [("file_id", "TEXT"), ("encrypted_path", "TEXT"), ("is_encrypted", "INTEGER DEFAULT 1")]:
        if col not in file_cols:
            cursor.execute(f"ALTER TABLE files ADD COLUMN {col} {col_def}")

    cursor.execute("PRAGMA table_info(trash_files)")
    trash_cols = [c[1] for c in cursor.fetchall()]
    for col, col_def in [("file_id", "TEXT")]:
        if col not in trash_cols:
            cursor.execute(f"ALTER TABLE trash_files ADD COLUMN {col} {col_def}")

    # Seed default user if not present
    cursor.execute("SELECT username, password FROM users WHERE username = ?", ("NitinMor",))
    existing_user = cursor.fetchone()
    if existing_user is None:
        pass_hash = hash_password("Nitin@1234")
        cursor.execute(
            "INSERT INTO users (username, password, email, phone, dob, is_verified) VALUES (?, ?, ?, ?, ?, ?)",
            ("NitinMor", pass_hash, "mornitin123@gmail.com", "+91 9876543210", "11/02/2004", 1)
        )
    elif not existing_user[1].startswith("scrypt$"):
        # Upgrade plain/bcrypt password to scrypt hash seamlessly
        pass_hash = hash_password("Nitin@1234")
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (pass_hash, "NitinMor"))

    # Seed default Admin employee and announcement
    cursor.execute("INSERT OR IGNORE INTO employees (employee_id, name, department, role, email, password) VALUES (?, ?, ?, ?, ?, ?)",
                   ("IT-ADMIN-01", "Nitin Mor", "Information Technology (IT)", "Department Admin", "nitin@phoenixshield.online", "admin123"))
    cursor.execute("INSERT OR IGNORE INTO announcements (title, message, created_at) VALUES (?, ?, ?)",
                   ("Q3 Security Audit", "Q3 Security Audit scheduled for Friday across all network endpoints. AES-256-GCM encryption active.", time.time()))

    conn.commit()
    conn.close()

init_db()

# ---------------------------------------------------------
# TRAFFIC MONITORING & THREAT DETECTION MIDDLEWARE
# ---------------------------------------------------------
@app.middleware("http")
async def monitor_traffic(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    path = request.url.path
    method = request.method

    threat_level = "Safe"
    suspicious_keywords = ["select", "union", "<script>", "drop", "admin--", "' OR '1'='1", "sleep(", "benchmark("]

    # Check for payload anomalies
    if detect_payload_anomaly(path) or any(kw in path.lower() for kw in suspicious_keywords):
        threat_level = "High (Hacker Detected!)"

    # Check for Canary Token honeypot trip
    if "canary" in path.lower() and not path.endswith("/events") and not path.endswith("/info"):
        threat_level = "Critical (Canary Honeytoken Triggered!)"

    response = await call_next(request)

    # Log requests excluding static Swagger docs
    if not path.startswith("/docs") and not path.startswith("/openapi.json"):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO traffic_logs (ip_address, endpoint, method, status, threat_level, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                (client_ip, path, method, str(response.status_code), threat_level, time.time())
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    return response

# ---------------------------------------------------------
# PYDANTIC DATA SCHEMAS
# ---------------------------------------------------------
class UserCredentials(BaseModel):
    username: str
    password: str
    email: str | None = None
    phone: str | None = None
    dob: str | None = None

class FolderCreate(BaseModel):
    name: str
    username: str

class QueryCreate(BaseModel):
    from_dept: str
    to_dept: str
    query_text: str

# ---------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------
def format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{round(size_bytes / 1024, 2)} KB"
    else:
        return f"{round(size_bytes / (1024 * 1024), 2)} MB"

# =========================================================
# WEB FRONTEND
# =========================================================
@app.get("/", response_class=HTMLResponse)
def read_root():
    file_path = os.path.join(TEMPLATE_DIR, "index.html")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>index.html not found</h3>"

# =========================================================
# AUTHENTICATION (DUAL SESSION COOKIE + JWT SUPPORT)
# =========================================================
@app.post("/api/private/register")
def register_user(creds: UserCredentials):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        password_hashed = hash_password(creds.password)
        cursor.execute(
            """
            INSERT INTO users (username, password, email, phone, dob, is_verified) 
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                creds.username,
                password_hashed,
                creds.email or f"{creds.username.lower()}@phoenixshield.online",
                creds.phone or "+91 9876543210",
                creds.dob or "11/02/2004",
                0
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists!")
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))
    conn.close()
    return {"message": "Account created successfully!"}


@app.post("/api/private/login")
async def login_user(request: Request, response: Response):
    # Support both JSON body and Form input
    username = None
    password = None

    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            data = await request.json()
            username = data.get("username")
            password = data.get("password")
        except Exception:
            pass
    elif "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form = await request.form()
            username = form.get("username")
            password = form.get("password")
        except Exception:
            pass

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password are required.")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT username, password, phone, dob, is_verified FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(password, user[1]):
        raise HTTPException(status_code=401, detail="Invalid username or password! Please register first if you don't have an account.")

    # 1. Create secure session cookie (Member 2 specification)
    session_token = create_session(DB_FILE, username)
    response.set_cookie(
        key="phoenix_session",
        value=session_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=86400
    )

    # 2. Generate signed JWT token (Member 1 specification)
    jwt_token = create_access_token(username=username, role="private_user")

    return {
        "message": "Login successful",
        "username": user[0],
        "token": jwt_token,
        "phone": user[2] or "+91 9876543210",
        "dob": user[3] or "11/02/2004",
        "is_verified": user[4]
    }


@app.post("/api/private/logout")
async def logout(request: Request, response: Response):
    delete_session(request, DB_FILE)
    response.delete_cookie(key="phoenix_session")
    return {"message": "Logout successful."}

# =========================================================
# CANARY HONEYTOKEN SYSTEM (MEMBER 2 SPECIFICATION)
# =========================================================
@app.get("/api/private/canary/info")
def canary_info():
    """Retrieve metadata about the decoy canary token."""
    return get_canary_info()


@app.get("/api/private/canary")
def trigger_canary_endpoint(request: Request):
    """Canary honeytrap endpoint triggered by unauthorized crawlers or attackers."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    username = request.headers.get("X-Username") or get_current_user_from_session(request, DB_FILE) or "unauthorized_probe"
    
    event = trigger_canary(username=username, client_ip=client_ip)
    return {
        "status": "ALERT",
        "message": "Canary token triggered. Unauthorized access detected.",
        "event_id": event["event_id"],
        "severity": "HIGH",
        "timestamp": event["timestamp"]
    }


@app.get("/api/private/canary/events")
def canary_events():
    """Returns log of all triggered canary alerts."""
    return get_canary_events()

# =========================================================
# MNC SOFTWARE UPGRADE & LICENSE VERIFICATION
# =========================================================
@app.get("/api/mnc/software-upgrade")
def get_software_upgrade(x_license_key: str = Header(None)):
    """Member 2 MNC software upgrade authorization check."""
    VALID_KEYS = ["MNC-SECURE-KEY-2026-X99", "ENTERPRISE-PRO-KEY"]
    if x_license_key not in VALID_KEYS:
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing enterprise license key."
        )

    return {
        "status": "authorized",
        "upgrade_version": "v2.4.0-enterprise",
        "patch_notes": "Advanced threat detection rules deployed via codebase sync. AES-256-GCM hardware acceleration enabled."
    }


@app.post("/api/enterprise/verify-key")
def verify_enterprise_key(payload: dict):
    """Member 1 Enterprise license verification."""
    key = payload.get("key")
    VALID_KEYS = ["MNC-SECURE-KEY-2026-X99", "ENTERPRISE-PRO-KEY"]
    if key not in VALID_KEYS:
        raise HTTPException(status_code=403, detail="Invalid corporate license key.")
    return {"status": "authorized"}

# =========================================================
# SECURE FILE MANAGEMENT (AES-256-GCM ENVELOPE ENCRYPTION)
# =========================================================
@app.post("/api/private/upload")
async def upload_user_data(
    request: Request,
    file: UploadFile = File(...),
    username: str = Form(None),
    folder_name: str = Form("None")
):
    """
    Encrypts uploaded file data with AES-256-GCM, stores wrapped encryption
    key using LocalKeyManager, saves metadata JSON and registers with DB.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    file_data = await file.read()
    if not file_data:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Determine user identity (supports Form username or authenticated session)
    resolved_user = username or get_current_user_from_session(request, DB_FILE) or "anonymous"

    # AI Anomaly check on upload
    anomaly_result = analyze_file_anomaly(file.filename, len(file_data))

    # Generate unique file ID & 256-bit AES key
    file_id = str(uuid.uuid4())
    encryption_key = generate_key()

    # Encrypt payload using AES-256-GCM
    encrypted_data = encrypt_file_data(file_data, encryption_key)

    # Save encrypted ciphertext
    encrypted_filename = f"{file_id}.enc"
    encrypted_path = os.path.join(ENCRYPTED_STORAGE_DIR, encrypted_filename)
    with open(encrypted_path, "wb") as f_enc:
        f_enc.write(encrypted_data)

    # Save encryption key securely using Master KEK wrapping
    key_manager.save_key(file_id, encryption_key)

    # Also keep a decrypted copy in UPLOAD_DIR for legacy view endpoints
    plain_upload_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(plain_upload_path, "wb") as f_plain:
        f_plain.write(file_data)

    # Determine MIME and file type
    mime_type, _ = mimetypes.guess_type(file.filename)
    file_type = "document"
    if mime_type:
        if mime_type.startswith("image/"):
            file_type = "image"
        elif mime_type.startswith("video/"):
            file_type = "video"

    size_bytes = len(file_data)
    size_str = format_size(size_bytes)

    # Save JSON metadata (Member 2 specification)
    metadata = {
        "file_id": file_id,
        "filename": file.filename,
        "file_type": file_type,
        "mime_type": mime_type,
        "original_size": size_bytes,
        "encrypted_size": len(encrypted_data),
        "encryption": "AES-256-GCM",
        "status": "encrypted",
        "owner": resolved_user,
        "folder_name": folder_name,
        "anomaly_flag": anomaly_result.get("anomaly_flag", False)
    }

    metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
    with open(metadata_path, "w", encoding="utf-8") as f_meta:
        json.dump(metadata, f_meta, indent=4)

    # Record in SQLite database (Member 1 specification)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO files (file_id, filename, username, folder_name, file_type, size_str, encrypted_path, is_encrypted)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        """,
        (file_id, file.filename, resolved_user, folder_name, file_type, size_str, encrypted_path)
    )
    conn.commit()
    conn.close()

    # Clear memory references
    del file_data
    del encryption_key
    del encrypted_data

    return {
        "file_id": file_id,
        "filename": file.filename,
        "file_type": file_type,
        "size": size_str,
        "encryption": "AES-256-GCM",
        "message": "File successfully encrypted with AES-256-GCM and securely stored."
    }


@app.get("/api/private/files")
async def list_files_session(request: Request):
    """Member 2 file list endpoint reading encrypted storage metadata."""
    username = get_current_user_from_session(request, DB_FILE)
    if not os.path.exists(METADATA_DIR):
        return []

    files = []
    for metadata_filename in os.listdir(METADATA_DIR):
        if not metadata_filename.endswith(".json"):
            continue

        metadata_path = os.path.join(METADATA_DIR, metadata_filename)
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            if username and meta.get("owner") and meta.get("owner") != username:
                continue

            files.append({
                "file_id": meta.get("file_id"),
                "filename": meta.get("filename"),
                "size": format_size(meta.get("original_size", 0)),
                "file_type": meta.get("file_type", "document"),
                "status": "Encrypted",
                "folder_name": meta.get("folder_name", "None")
            })
        except Exception:
            continue

    return files


@app.get("/api/private/files/{username}")
def list_files_for_user(username: str):
    """Member 1 file list endpoint reading DB records."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, folder_name, file_type, size_str, file_id FROM files WHERE username = ?", (username,))
    rows = cursor.fetchall()
    conn.close()
    return [{
        "filename": r[0],
        "folder_name": r[1],
        "file_type": r[2],
        "size": r[3],
        "file_id": r[4],
        "status": "Encrypted (AES-256-GCM)"
    } for r in rows]


@app.get("/api/private/download/{file_id}")
async def download_encrypted_file(file_id: str, request: Request):
    """Member 2 secure decryption & download endpoint."""
    metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")
    if not os.path.exists(metadata_path):
        raise HTTPException(status_code=404, detail="File metadata not found.")

    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)

    encrypted_path = os.path.join(ENCRYPTED_STORAGE_DIR, f"{file_id}.enc")
    if not os.path.exists(encrypted_path):
        raise HTTPException(status_code=404, detail="Encrypted file not found.")

    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()

    try:
        encryption_key = key_manager.load_key(file_id)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Encryption key not found.")

    try:
        decrypted_data = decrypt_file_data(encrypted_data, encryption_key)
    except Exception:
        raise HTTPException(status_code=500, detail="Decryption failed. Key mismatch or corrupted data.")

    temp_path = os.path.join(TEMPORARY_DIR, f"{file_id}_{metadata['filename']}")
    with open(temp_path, "wb") as f_temp:
        f_temp.write(decrypted_data)

    return FileResponse(
        path=temp_path,
        filename=metadata["filename"],
        media_type=metadata.get("mime_type") or "application/octet-stream"
    )


@app.get("/download/{filename}")
def download_by_filename(filename: str):
    """Member 1 download endpoint with automatic fallback to decryption."""
    # First check decrypted upload dir
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='application/octet-stream', filename=filename)

    # Search in metadata for matching encrypted file
    if os.path.exists(METADATA_DIR):
        for meta_file in os.listdir(METADATA_DIR):
            if meta_file.endswith(".json"):
                try:
                    with open(os.path.join(METADATA_DIR, meta_file), "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    if meta.get("filename") == filename:
                        file_id = meta.get("file_id")
                        key = key_manager.load_key(file_id)
                        with open(os.path.join(ENCRYPTED_STORAGE_DIR, f"{file_id}.enc"), "rb") as enc_f:
                            dec_data = decrypt_file_data(enc_f.read(), key)
                        temp_path = os.path.join(TEMPORARY_DIR, f"{file_id}_{filename}")
                        with open(temp_path, "wb") as t_f:
                            t_f.write(dec_data)
                        return FileResponse(temp_path, media_type='application/octet-stream', filename=filename)
                except Exception:
                    continue

    raise HTTPException(status_code=404, detail="File not found")


@app.get("/uploads/{filename}")
def view_file(filename: str):
    """Member 1 preview endpoint."""
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    return download_by_filename(filename)


@app.delete("/api/private/files/{file_id}")
async def delete_file_by_id(file_id: str, request: Request):
    """Member 2 delete endpoint by file_id."""
    encrypted_path = os.path.join(ENCRYPTED_STORAGE_DIR, f"{file_id}.enc")
    key_path = os.path.join(KEY_STORAGE_DIR, f"{file_id}.key")
    metadata_path = os.path.join(METADATA_DIR, f"{file_id}.json")

    deleted = False
    if os.path.exists(encrypted_path):
        os.remove(encrypted_path)
        deleted = True
    if os.path.exists(key_path):
        os.remove(key_path)
        deleted = True
    if os.path.exists(metadata_path):
        os.remove(metadata_path)
        deleted = True

    # Also clean up DB
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM files WHERE file_id = ?", (file_id,))
    conn.commit()
    conn.close()

    if deleted:
        return {"message": "Encrypted file and key purged successfully."}
    raise HTTPException(status_code=404, detail="File not found.")


@app.delete("/api/private/files/{username}/{filename}")
def delete_file_to_trash(username: str, filename: str):
    """Member 1 delete endpoint moving file to trash."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT size_str, file_id FROM files WHERE username = ? AND filename = ?", (username, filename))
    file_row = cursor.fetchone()
    if file_row:
        cursor.execute(
            "INSERT INTO trash_files (file_id, filename, username, size_str) VALUES (?, ?, ?, ?)",
            (file_row[1], filename, username, file_row[0])
        )
        cursor.execute("DELETE FROM files WHERE username = ? AND filename = ?", (username, filename))
        conn.commit()
    conn.close()
    return {"message": "Moved to Trash"}


@app.get("/api/private/trash/{username}")
def get_trash_files(username: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, size_str FROM trash_files WHERE username = ?", (username,))
    rows = cursor.fetchall()
    conn.close()
    return [{"filename": r[0], "size": r[1]} for r in rows]

# =========================================================
# FOLDERS MANAGEMENT
# =========================================================
@app.post("/api/private/folders")
def create_folder(folder: FolderCreate):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO folders (name, username) VALUES (?, ?)", (folder.name, folder.username))
    conn.commit()
    conn.close()
    return {"message": f"Folder '{folder.name}' created!"}


@app.get("/api/private/folders/{username}")
def list_folders(username: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM folders WHERE username = ?", (username,))
    rows = cursor.fetchall()
    conn.close()
    return [row[0] for row in rows]


@app.delete("/api/private/folders/{username}/{foldername}")
def delete_folder(username: str, foldername: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM folders WHERE username = ? AND name = ?", (username, foldername))
    cursor.execute("DELETE FROM files WHERE username = ? AND folder_name = ?", (username, foldername))
    conn.commit()
    conn.close()
    return {"message": "Folder deleted successfully"}

# =========================================================
# ENTERPRISE GATEWAY & MODULES (MEMBER 1 SUITE)
# =========================================================
@app.post("/api/enterprise/login")
def login_enterprise(payload: dict):
    emp_id = payload.get("employee_id")
    password = payload.get("password")
    department = payload.get("department")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT employee_id, name, department, role, email FROM employees WHERE employee_id = ? AND password = ?", (emp_id, password))
    emp = cursor.fetchone()

    if not emp:
        cursor.execute(
            "INSERT OR IGNORE INTO employees (employee_id, name, department, role, email, password) VALUES (?, ?, ?, ?, ?, ?)",
            (emp_id, emp_id, department, "Employee", f"{emp_id.lower()}@phoenixshield.online", password)
        )
        conn.commit()
        cursor.execute("SELECT employee_id, name, department, role, email FROM employees WHERE employee_id = ?", (emp_id,))
        emp = cursor.fetchone()

    conn.close()
    if emp:
        return {
            "employee": {
                "employee_id": emp[0],
                "name": emp[1],
                "department": emp[2],
                "role": emp[3],
                "email": emp[4]
            }
        }
    raise HTTPException(status_code=401, detail="Invalid employee credentials.")


@app.get("/api/enterprise/dashboard/{employee_id}")
def get_ent_dashboard(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM employees")
    emp_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM tasks WHERE status != 'Done'")
    pending_tasks = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM support_tickets WHERE status != 'Resolved'")
    open_tickets = cursor.fetchone()[0]
    cursor.execute("SELECT title, message FROM announcements ORDER BY id DESC LIMIT 5")
    announcements = [{"title": r[0], "message": r[1]} for r in cursor.fetchall()]
    conn.close()
    return {
        "counts": {
            "employees": emp_count,
            "pending_tasks": pending_tasks,
            "open_tickets": open_tickets,
            "system_uptime": "99.9%"
        },
        "announcements": announcements
    }


@app.get("/api/enterprise/employees")
def list_enterprise_employees():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT employee_id, name, department, role, email FROM employees")
    rows = cursor.fetchall()
    conn.close()
    return [{"employee_id": r[0], "name": r[1], "department": r[2], "role": r[3], "email": r[4]} for r in rows]


@app.post("/api/enterprise/employees")
def create_enterprise_employee(payload: dict, actor_id: str = "System"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO employees (employee_id, name, department, role, email, password) VALUES (?, ?, ?, ?, ?, ?)",
            (payload.get("employee_id"), payload.get("name"), payload.get("department"), payload.get("role"), payload.get("email"), payload.get("password", "welcome123"))
        )
        cursor.execute(
            "INSERT INTO audit_logs (employee_id, action, entity, details, created_at) VALUES (?, ?, ?, ?, ?)",
            (actor_id, "CREATE", "Employee", f"Created employee {payload.get('employee_id')}", time.time())
        )
        conn.commit()
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=400, detail=str(e))
    conn.close()
    return {"message": "Employee created successfully"}


@app.get("/api/enterprise/attendance/{employee_id}")
def get_attendance(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT work_date, check_in, check_out, status FROM attendance WHERE employee_id = ? ORDER BY id DESC", (employee_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"work_date": r[0], "check_in": r[1], "check_out": r[2], "status": r[3]} for r in rows]


@app.post("/api/enterprise/attendance/{employee_id}")
def mark_attendance(employee_id: str, payload: dict):
    action = payload.get("action")
    today = time.strftime("%Y-%m-%d")
    current_time = time.strftime("%H:%M:%S")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, check_in FROM attendance WHERE employee_id = ? AND work_date = ?", (employee_id, today))
    row = cursor.fetchone()
    if action == "check-in":
        if row:
            conn.close()
            raise HTTPException(status_code=400, detail="Already checked in today.")
        cursor.execute("INSERT INTO attendance (employee_id, work_date, check_in, status) VALUES (?, ?, ?, ?)",
                       (employee_id, today, current_time, "Present"))
    elif action == "check-out":
        if not row:
            conn.close()
            raise HTTPException(status_code=400, detail="No check-in record found for today.")
        cursor.execute("UPDATE attendance SET check_out = ? WHERE id = ?", (current_time, row[0]))
    conn.commit()
    conn.close()
    return {"message": f"Successfully recorded {action}"}


@app.get("/api/enterprise/leave/{employee_id}")
def get_leave(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, leave_type, start_date, end_date, reason, status FROM leave_requests WHERE employee_id = ? ORDER BY id DESC", (employee_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "leave_type": r[1], "start_date": r[2], "end_date": r[3], "reason": r[4], "status": r[5]} for r in rows]


@app.post("/api/enterprise/leave/{employee_id}")
def apply_leave(employee_id: str, payload: dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO leave_requests (employee_id, leave_type, start_date, end_date, reason, status) VALUES (?, ?, ?, ?, ?, ?)",
        (employee_id, payload.get("leave_type"), payload.get("start_date"), payload.get("end_date"), payload.get("reason"), "Pending")
    )
    conn.commit()
    conn.close()
    return {"message": "Leave application submitted."}


@app.get("/api/enterprise/tasks/{employee_id}")
def get_tasks(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, description, assigned_to, priority, due_date, status FROM tasks")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "description": r[2], "assigned_to": r[3], "priority": r[4], "due_date": r[5], "status": r[6]} for r in rows]


@app.post("/api/enterprise/tasks")
def create_task(payload: dict, actor_id: str = "System"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO tasks (title, description, assigned_to, priority, due_date, status) VALUES (?, ?, ?, ?, ?, ?)",
        (payload.get("title"), payload.get("description"), payload.get("assigned_to"), payload.get("priority"), payload.get("due_date"), "To Do")
    )
    conn.commit()
    conn.close()
    return {"message": "Task created successfully"}


@app.patch("/api/enterprise/tasks/{task_id}")
def update_task_status(task_id: int, payload: dict, actor_id: str = "System"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE tasks SET status = ? WHERE id = ?", (payload.get("status"), task_id))
    conn.commit()
    conn.close()
    return {"message": "Task updated"}


@app.get("/api/enterprise/projects/{employee_id}")
def get_projects(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, description, progress FROM projects")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "description": r[2], "progress": r[3]} for r in rows]


@app.post("/api/enterprise/projects")
def create_project(payload: dict, actor_id: str = "System"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO projects (name, description, progress) VALUES (?, ?, ?)",
        (payload.get("name"), payload.get("description"), payload.get("progress", 0))
    )
    conn.commit()
    conn.close()
    return {"message": "Project created"}


@app.patch("/api/enterprise/projects/{project_id}")
def update_project(project_id: int, payload: dict, actor_id: str = "System"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE projects SET progress = ? WHERE id = ?", (payload.get("progress"), project_id))
    conn.commit()
    conn.close()
    return {"message": "Project progress updated"}


@app.get("/api/enterprise/messages/{employee_id}")
def get_messages(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT sender_employee_id, message, created_at FROM messages ORDER BY id DESC LIMIT 20")
    rows = cursor.fetchall()
    conn.close()
    return [{"sender_employee_id": r[0], "message": r[1], "created_at": r[2]} for r in rows]


@app.post("/api/enterprise/messages/{employee_id}")
def post_message(employee_id: str, payload: dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO messages (sender_employee_id, message, created_at) VALUES (?, ?, ?)",
        (employee_id, payload.get("message"), time.time())
    )
    conn.commit()
    conn.close()
    return {"message": "Message posted"}


@app.get("/api/enterprise/meetings/{employee_id}")
def get_meetings(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, meeting_date, meeting_time, description, organizer_employee_id, status FROM meetings ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "meeting_date": r[2], "meeting_time": r[3], "description": r[4], "organizer_employee_id": r[5], "status": r[6]} for r in rows]


@app.post("/api/enterprise/meetings/{employee_id}")
def create_meeting(employee_id: str, payload: dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO meetings (title, meeting_date, meeting_time, description, organizer_employee_id, status) VALUES (?, ?, ?, ?, ?, ?)",
        (payload.get("title"), payload.get("meeting_date"), payload.get("meeting_time"), payload.get("description"), employee_id, "Scheduled")
    )
    conn.commit()
    conn.close()
    return {"message": "Meeting scheduled"}


@app.patch("/api/enterprise/meetings/{meeting_id}")
def update_meeting(meeting_id: int, payload: dict, actor_id: str = "System"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    if payload.get("status"):
        cursor.execute("UPDATE meetings SET status = ? WHERE id = ?", (payload.get("status"), meeting_id))
    if payload.get("meeting_date") and payload.get("meeting_time"):
        cursor.execute("UPDATE meetings SET meeting_date = ?, meeting_time = ? WHERE id = ?", (payload.get("meeting_date"), payload.get("meeting_time"), meeting_id))
    conn.commit()
    conn.close()
    return {"message": "Meeting updated"}


@app.get("/api/enterprise/payroll/{employee_id}")
def get_payroll(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT month, basic, allowances, deductions, net, status FROM payroll WHERE employee_id = ?", (employee_id,))
    rows = cursor.fetchall()
    if not rows:
        rows = [("September 2026", 75000, 15000, 5000, 85000, "Disbursed")]
    conn.close()
    return [{"month": r[0], "basic": r[1], "allowances": r[2], "deductions": r[3], "net": r[4], "status": r[5]} for r in rows]


@app.get("/api/enterprise/documents/{employee_id}")
def get_documents(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, category FROM documents WHERE employee_id = ?", (employee_id,))
    rows = cursor.fetchall()
    if not rows:
        rows = [("Employee_Handbook_2026.pdf", "Policy"), ("NDA_Agreement.pdf", "Legal")]
    conn.close()
    return [{"filename": r[0], "category": r[1]} for r in rows]


@app.get("/api/enterprise/training/{employee_id}")
def get_training(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, description, progress, status FROM training WHERE employee_id = ?", (employee_id,))
    rows = cursor.fetchall()
    if not rows:
        cursor.execute(
            "INSERT INTO training (employee_id, title, description, progress, status) VALUES (?, ?, ?, ?, ?)",
            (employee_id, "Advanced Cybersecurity Protocols", "Mandatory corporate defense training module.", 45, "In Progress")
        )
        conn.commit()
        cursor.execute("SELECT id, title, description, progress, status FROM training WHERE employee_id = ?", (employee_id,))
        rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "description": r[2], "progress": r[3], "status": r[4]} for r in rows]


@app.patch("/api/enterprise/training/{id}")
def update_training(id: int, employee_id: str, progress: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    status_str = "Completed" if progress >= 100 else "In Progress"
    cursor.execute("UPDATE training SET progress = ?, status = ? WHERE id = ?", (progress, status_str, id))
    conn.commit()
    conn.close()
    return {"message": "Training updated"}


@app.get("/api/enterprise/kpi/{employee_id}")
def get_kpi(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT title, target, progress, review_note FROM kpi WHERE employee_id = ?", (employee_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"title": r[0], "target": r[1], "progress": r[2], "review_note": r[3]} for r in rows]


@app.post("/api/enterprise/kpi/{employee_id}")
def save_kpi(employee_id: str, payload: dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO kpi (employee_id, title, target, progress, review_note) VALUES (?, ?, ?, ?, ?)",
        (employee_id, payload.get("title"), payload.get("target"), payload.get("progress"), payload.get("review_note"))
    )
    conn.commit()
    conn.close()
    return {"message": "KPI saved"}


@app.get("/api/enterprise/tickets/{employee_id}")
def get_tickets(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, ticket_no, category, subject, description, priority, status, created_at FROM support_tickets WHERE employee_id = ? ORDER BY id DESC", (employee_id,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "ticket_no": r[1], "category": r[2], "subject": r[3], "description": r[4], "priority": r[5], "status": r[6], "created_at": r[7]} for r in rows]


@app.post("/api/enterprise/tickets/{employee_id}")
def create_ticket(employee_id: str, payload: dict):
    ticket_no = f"TICK-{int(time.time())}"
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO support_tickets (ticket_no, employee_id, category, subject, description, priority, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (ticket_no, employee_id, payload.get("category"), payload.get("subject"), payload.get("description"), payload.get("priority"), "Open", time.time())
    )
    conn.commit()
    conn.close()
    return {"message": "Ticket created successfully"}


@app.patch("/api/enterprise/tickets/{id}")
def update_ticket(id: int, payload: dict, actor_id: str = "System"):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE support_tickets SET status = ? WHERE id = ?", (payload.get("status"), id))
    conn.commit()
    conn.close()
    return {"message": "Ticket resolved"}


@app.get("/api/enterprise/audit/{employee_id}")
def get_audit_logs(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT employee_id, action, entity, details, created_at FROM audit_logs ORDER BY id DESC LIMIT 30")
    rows = cursor.fetchall()
    conn.close()
    return [{"employee_id": r[0], "action": r[1], "entity": r[2], "details": r[3], "created_at": r[4]} for r in rows]


@app.get("/api/enterprise/notifications/{employee_id}")
def get_notifications(employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, message, is_read FROM notifications WHERE employee_id = ? OR employee_id = 'ALL' ORDER BY id DESC", (employee_id,))
    rows = cursor.fetchall()
    if not rows:
        rows = [(1, "Welcome to Enterprise", "Your corporate gateway account is fully active and secured.", 0)]
    conn.close()
    return [{"id": r[0], "title": r[1], "message": r[2], "is_read": r[3]} for r in rows]


@app.patch("/api/enterprise/notifications/{id}")
def mark_notification(id: int, employee_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    return {"message": "Marked as read"}


@app.get("/api/security/traffic-logs")
def get_traffic_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, endpoint, method, status, threat_level, timestamp FROM traffic_logs ORDER BY id DESC LIMIT 30")
    rows = cursor.fetchall()
    conn.close()
    return [{"ip": r[0], "endpoint": r[1], "method": r[2], "status": r[3], "threat": r[4], "time": r[5]} for r in rows]