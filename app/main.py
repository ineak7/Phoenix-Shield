from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import shutil
import os
import sqlite3
import mimetypes
import time

from app.anomaly_detection import detect_payload_anomaly, analyze_file_anomaly

app = FastAPI(title="Phoenix Shield API", version="4.3.0")

UPLOAD_DIR = "app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
DB_FILE = "app/users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Core tables
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY, 
                        password TEXT,
                        phone TEXT,
                        dob TEXT,
                        is_verified INTEGER DEFAULT 0
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS folders (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        name TEXT, 
                        username TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT,
                        username TEXT,
                        folder_name TEXT,
                        file_type TEXT,
                        size_str TEXT
                    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS trash_files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    
    # Enterprise Data Models / Tables
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

    # Seed default Admin employee for testing
    cursor.execute("INSERT OR IGNORE INTO employees (employee_id, name, department, role, email, password) VALUES (?, ?, ?, ?, ?, ?)",
                   ("IT-ADMIN-01", "Nitin Mor", "Information Technology (IT)", "Department Admin", "nitin@phoenixshield.online", "admin123"))
    cursor.execute("INSERT OR IGNORE INTO announcements (title, message, created_at) VALUES (?, ?, ?)",
                   ("Q3 Security Audit", "Q3 Security Audit scheduled for Friday across all network endpoints.", time.time()))
    
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
    phone: str = None
    dob: str = None

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
        cursor.execute("INSERT INTO users (username, password, phone, dob, is_verified) VALUES (?, ?, ?, ?, ?)",
                       (creds.username, creds.password, creds.phone, creds.dob, 0))
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
    cursor.execute("SELECT username, phone, dob, is_verified FROM users WHERE username = ? AND password = ?", (creds.username, creds.password))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {
            "message": "Login successful",
            "username": user[0],
            "phone": user[1] or "+91 9876543210",
            "dob": user[2] or "11/02/2004",
            "is_verified": user[3]
        }
    raise HTTPException(status_code=401, detail="Invalid username or password! Please register first if you don't have an account.")

# --- File Upload & Management Routes ---
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

@app.get("/download/{filename}")
def download_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type='application/octet-stream', filename=filename)
    raise HTTPException(status_code=404, detail="File not found")

@app.get("/uploads/{filename}")
def view_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="File not found")

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
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT size_str FROM files WHERE username = ? AND filename = ?", (username, filename))
    file_row = cursor.fetchone()
    if file_row:
        cursor.execute("INSERT INTO trash_files (filename, username, size_str) VALUES (?, ?, ?)", (filename, username, file_row[0]))
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

# --- Enterprise Gateway & Modules Endpoints ---
@app.post("/api/enterprise/verify-key")
def verify_enterprise_key(payload: dict):
    key = payload.get("key")
    VALID_KEYS = ["MNC-SECURE-KEY-2026-X99", "ENTERPRISE-PRO-KEY"]
    if key not in VALID_KEYS:
        raise HTTPException(status_code=403, detail="Invalid corporate license key.")
    return {"status": "authorized"}

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
        cursor.execute("INSERT OR IGNORE INTO employees (employee_id, name, department, role, email, password) VALUES (?, ?, ?, ?, ?, ?)",
                       (emp_id, emp_id, department, "Employee", f"{emp_id.lower()}@phoenixshield.online", password))
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
        cursor.execute("INSERT INTO employees (employee_id, name, department, role, email, password) VALUES (?, ?, ?, ?, ?, ?)",
                       (payload.get("employee_id"), payload.get("name"), payload.get("department"), payload.get("role"), payload.get("email"), payload.get("password", "welcome123")))
        cursor.execute("INSERT INTO audit_logs (employee_id, action, entity, details, created_at) VALUES (?, ?, ?, ?, ?)",
                       (actor_id, "CREATE", "Employee", f"Created employee {payload.get('employee_id')}", time.time()))
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
    cursor.execute("INSERT INTO leave_requests (employee_id, leave_type, start_date, end_date, reason, status) VALUES (?, ?, ?, ?, ?, ?)",
                   (employee_id, payload.get("leave_type"), payload.get("start_date"), payload.get("end_date"), payload.get("reason"), "Pending"))
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
    cursor.execute("INSERT INTO tasks (title, description, assigned_to, priority, due_date, status) VALUES (?, ?, ?, ?, ?, ?)",
                   (payload.get("title"), payload.get("description"), payload.get("assigned_to"), payload.get("priority"), payload.get("due_date"), "To Do"))
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
    cursor.execute("INSERT INTO projects (name, description, progress) VALUES (?, ?, ?)",
                   (payload.get("name"), payload.get("description"), payload.get("progress", 0)))
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
    cursor.execute("INSERT INTO messages (sender_employee_id, message, created_at) VALUES (?, ?, ?)",
                   (employee_id, payload.get("message"), time.time()))
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
    cursor.execute("INSERT INTO meetings (title, meeting_date, meeting_time, description, organizer_employee_id, status) VALUES (?, ?, ?, ?, ?, ?)",
                   (payload.get("title"), payload.get("meeting_date"), payload.get("meeting_time"), payload.get("description"), employee_id, "Scheduled"))
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
        cursor.execute("INSERT INTO training (employee_id, title, description, progress, status) VALUES (?, ?, ?, ?, ?)",
                       (employee_id, "Advanced Cybersecurity Protocols", "Mandatory corporate defense training module.", 45, "In Progress"))
        conn.commit()
        cursor.execute("SELECT id, title, description, progress, status FROM training WHERE employee_id = ?", (employee_id,))
        rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "title": r[1], "description": r[2], "progress": r[3], "status": r[4]} for r in rows]

@app.patch("/api/enterprise/training/{id}")
def update_training(id: int, employee_id: str, progress: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    status = "Completed" if progress >= 100 else "In Progress"
    cursor.execute("UPDATE training SET progress = ?, status = ? WHERE id = ?", (progress, status, id))
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
    cursor.execute("INSERT INTO kpi (employee_id, title, target, progress, review_note) VALUES (?, ?, ?, ?, ?)",
                   (employee_id, payload.get("title"), payload.get("target"), payload.get("progress"), payload.get("review_note")))
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
    cursor.execute("INSERT INTO support_tickets (ticket_no, employee_id, category, subject, description, priority, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (ticket_no, employee_id, payload.get("category"), payload.get("subject"), payload.get("description"), payload.get("priority"), "Open", time.time()))
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
