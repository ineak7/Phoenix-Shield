from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Header, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import shutil
import os
import sqlite3
import mimetypes
import time

from app.anomaly_detection import detect_payload_anomaly, analyze_file_anomaly

app = FastAPI(title="Phoenix Shield API", version="4.1.0")

UPLOAD_DIR = "app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
DB_FILE = "app/users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS folders (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, username TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS dept_queries (id INTEGER PRIMARY KEY AUTOINCREMENT, from_dept TEXT, to_dept TEXT, query_text TEXT, status TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS traffic_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT, endpoint TEXT, method TEXT, status TEXT, threat_level TEXT, timestamp REAL)''')
    
    # Files table updated with folder support
    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT,
                        username TEXT,
                        folder_name TEXT,
                        file_type TEXT,
                        size_str TEXT
                    )''')
    
    cursor.execute("INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)", ("NitinMor", "Nitin@1234"))
    conn.commit()
    conn.close()

init_db()

@app.middleware("http")
async def monitor_traffic(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    path = request.url.path
    method = request.method
    
    threat_level = "Safe"
    suspicious_keywords = ["select", "union", "<script>", "drop", "admin--", "' OR '1'='1"]
    if detect_payload_anomaly(path) or any(kw in path.lower() for kw in suspicious_keywords):
        threat_level = "High (Hacker Detected!)"
    
    response = await call_next(request)
    
    if not path.startswith("/docs") and not path.startswith("/openapi.json"):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO traffic_logs (ip_address, endpoint, method, status, threat_level, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                       (client_ip, path, method, str(response.status_code), threat_level, time.time()))
        conn.commit()
        conn.close()
        
    return response

class UserCredentials(BaseModel):
    username: str
    password: str

class FolderCreate(BaseModel):
    name: str
    username: str

class QueryCreate(BaseModel):
    from_dept: str
    to_dept: str
    query_text: str

@app.get("/", response_class=HTMLResponse)
def read_root():
    file_path = os.path.join("app", "templates", "index.html")
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h3>index.html not found</h3>"

@app.post("/api/private/register")
def register_user(creds: UserCredentials):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (creds.username, creds.password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username already exists!")
    conn.close()
    return {"message": "Account created successfully!"}

@app.post("/api/private/login")
def login_user(creds: UserCredentials):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (creds.username, creds.password))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"message": "Login successful", "username": creds.username}
    raise HTTPException(status_code=401, detail="Invalid credentials!")

# --- Updated File Upload with Folder & User Mapping ---
@app.post("/api/private/upload")
def upload_user_data(file: UploadFile = File(...), username: str = Form(...), folder_name: str = Form("None")):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    size_bytes = os.path.getsize(file_path)
    size_mb = round(size_bytes / (1024 * 1024), 2)
    size_str = f"{round(size_bytes / 1024, 2)} KB" if size_mb < 0.1 else f"{size_mb} MB"
    
    mime_type, _ = mimetypes.guess_type(file.filename)
    file_type = "document"
    if mime_type:
        if mime_type.startswith("image/"): file_type = "image"
        elif mime_type.startswith("video/"): file_type = "video"

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO files (filename, username, folder_name, file_type, size_str) VALUES (?, ?, ?, ?, ?)",
                   (file.filename, username, folder_name, file_type, size_str))
    conn.commit()
    conn.close()

    return {"filename": file.filename, "message": "Uploaded & Secured!"}

@app.get("/api/private/files/{username}")
def list_files(username: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT filename, folder_name, file_type, size_str FROM files WHERE username = ?", (username,))
    rows = cursor.fetchall()
    conn.close()
    return [{"filename": r[0], "folder_name": r[1], "file_type": r[2], "size": r[3]} for r in rows]

@app.delete("/api/private/files/{username}/{filename}")
def delete_file(username: str, filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM files WHERE username = ? AND filename = ?", (username, filename))
    conn.commit()
    conn.close()
    return {"message": "Deleted"}

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

@app.post("/api/enterprise/verify-key")
def verify_enterprise_key(payload: dict):
    key = payload.get("key")
    VALID_KEYS = ["MNC-SECURE-KEY-2026-X99", "ENTERPRISE-PRO-KEY"]
    if key not in VALID_KEYS:
        raise HTTPException(status_code=403, detail="Invalid corporate license key.")
    return {"status": "authorized"}

@app.post("/api/enterprise/query")
def raise_department_query(q: QueryCreate):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO dept_queries (from_dept, to_dept, query_text, status) VALUES (?, ?, ?, ?)", 
                   (q.from_dept, q.to_dept, q.query_text, "Pending"))
    conn.commit()
    conn.close()
    return {"message": "Query raised successfully!"}

@app.get("/api/enterprise/queries/{dept}")
def get_department_queries(dept: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, from_dept, query_text, status FROM dept_queries WHERE to_dept = ?", (dept,))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "from_dept": r[1], "query_text": r[2], "status": r[3]} for r in rows]

@app.get("/api/security/traffic-logs")
def get_traffic_logs():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT ip_address, endpoint, method, status, threat_level, timestamp FROM traffic_logs ORDER BY id DESC LIMIT 30")
    rows = cursor.fetchall()
    conn.close()
    return [{"ip": r[0], "endpoint": r[1], "method": r[2], "status": r[3], "threat": r[4], "time": r[5]} for r in rows]