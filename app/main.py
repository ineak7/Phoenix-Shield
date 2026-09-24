from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
import shutil
import os
import sqlite3
import mimetypes
import time
import hashlib
from typing import Optional

from app.anomaly_detection import detect_payload_anomaly, analyze_file_anomaly

app = FastAPI(title="Phoenix Shield API", version="5.0.0")

UPLOAD_DIR = "app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
DB_FILE = "app/users.db"

# ---------------- DATABASE ----------------
def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()

def init_db():
    conn = db()
    c = conn.cursor()
    
    # Base tables with safe column checks to prevent migration crashes on Render
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password TEXT, phone TEXT, dob TEXT, is_verified INTEGER DEFAULT 0)''')
    
    # Safe check and add columns if missing in existing database
    existing_cols = [row[1] for row in c.execute("PRAGMA table_info(users)").fetchall()]
    if "phone" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN phone TEXT")
    if "dob" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN dob TEXT")
    if "is_verified" not in existing_cols:
        c.execute("ALTER TABLE users ADD COLUMN is_verified INTEGER DEFAULT 0")

    c.execute('''CREATE TABLE IF NOT EXISTS folders (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, username TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS dept_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT, from_dept TEXT, to_dept TEXT, query_text TEXT, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS traffic_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ip_address TEXT, endpoint TEXT, method TEXT,
        status TEXT, threat_level TEXT, timestamp REAL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, username TEXT, folder_name TEXT,
        file_type TEXT, size_str TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS trash_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, username TEXT, size_str TEXT)''')

    # Enterprise tables
    c.execute('''CREATE TABLE IF NOT EXISTS employees (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL, department TEXT NOT NULL, role TEXT NOT NULL,
        email TEXT, password_hash TEXT NOT NULL, created_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL,
        work_date TEXT NOT NULL, check_in TEXT, check_out TEXT, status TEXT DEFAULT 'Present',
        UNIQUE(employee_id, work_date))''')
    c.execute('''CREATE TABLE IF NOT EXISTS leave_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL,
        leave_type TEXT NOT NULL, start_date TEXT NOT NULL, end_date TEXT NOT NULL,
        reason TEXT, status TEXT DEFAULT 'Pending', created_at REAL NOT NULL, updated_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT, owner_employee_id TEXT NOT NULL,
        assigned_to TEXT NOT NULL, title TEXT NOT NULL, description TEXT, priority TEXT DEFAULT 'Medium',
        due_date TEXT, status TEXT DEFAULT 'To Do', created_at REAL NOT NULL, updated_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT, owner_employee_id TEXT NOT NULL,
        name TEXT NOT NULL, description TEXT, progress INTEGER DEFAULT 0,
        created_at REAL NOT NULL, updated_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT, sender_employee_id TEXT NOT NULL,
        department TEXT NOT NULL, message TEXT NOT NULL, created_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS meetings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, organizer_employee_id TEXT NOT NULL,
        title TEXT NOT NULL, meeting_date TEXT NOT NULL, meeting_time TEXT NOT NULL,
        description TEXT, status TEXT DEFAULT 'Scheduled', created_at REAL NOT NULL, updated_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS meeting_attendees (
        id INTEGER PRIMARY KEY AUTOINCREMENT, meeting_id INTEGER NOT NULL, employee_id TEXT NOT NULL,
        UNIQUE(meeting_id, employee_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS tickets (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_no TEXT UNIQUE NOT NULL,
        employee_id TEXT NOT NULL, department TEXT NOT NULL, category TEXT NOT NULL,
        subject TEXT NOT NULL, description TEXT NOT NULL, priority TEXT DEFAULT 'Medium',
        status TEXT DEFAULT 'Open', created_at REAL NOT NULL, updated_at REAL NOT NULL,
        resolution TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL,
        title TEXT NOT NULL, message TEXT NOT NULL, is_read INTEGER DEFAULT 0, created_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL,
        action TEXT NOT NULL, entity TEXT NOT NULL, entity_id TEXT, details TEXT, created_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS announcements (
        id INTEGER PRIMARY KEY AUTOINCREMENT, department TEXT, title TEXT NOT NULL,
        message TEXT NOT NULL, created_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS payroll (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL,
        month TEXT NOT NULL, basic REAL DEFAULT 0, allowances REAL DEFAULT 0,
        deductions REAL DEFAULT 0, net REAL DEFAULT 0, status TEXT DEFAULT 'Processed')''')
    c.execute('''CREATE TABLE IF NOT EXISTS training_courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT,
        department TEXT, progress_default INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS training_enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT, course_id INTEGER NOT NULL, employee_id TEXT NOT NULL,
        progress INTEGER DEFAULT 0, status TEXT DEFAULT 'In Progress',
        UNIQUE(course_id, employee_id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS kpi_goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL, title TEXT NOT NULL,
        target TEXT, progress INTEGER DEFAULT 0, review_note TEXT, updated_at REAL NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS corporate_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT, employee_id TEXT NOT NULL,
        filename TEXT NOT NULL, category TEXT DEFAULT 'General', created_at REAL NOT NULL)''')

    # Existing demo user retained for compatibility.
    c.execute("INSERT OR IGNORE INTO users (username,password,phone,dob,is_verified) VALUES (?,?,?,?,1)",
              ("NitinMor", "Nitin@1234", "+919876543210", "11/02/2004"))

    # Seed enterprise demo employees.
    demo = [
        ("IT-ADMIN-01", "IT Administrator", "Information Technology (IT)", "Department Admin", "it.admin@phoenixshield.online", "Admin@123"),
        ("SEC-ADMIN-01", "Security Administrator", "Cybersecurity", "Department Admin", "security.admin@phoenixshield.online", "Admin@123"),
        ("HR-ADMIN-01", "HR Administrator", "Human Resources (HR)", "Department Admin", "hr.admin@phoenixshield.online", "Admin@123"),
        ("FIN-ADMIN-01", "Finance Administrator", "Finance & Accounts", "Department Admin", "finance.admin@phoenixshield.online", "Admin@123"),
        ("SALES-ADMIN-01", "Sales Administrator", "Sales", "Department Admin", "sales.admin@phoenixshield.online", "Admin@123"),
    ]
    for emp in demo:
        c.execute("INSERT OR IGNORE INTO employees (employee_id,name,department,role,email,password_hash,created_at) VALUES (?,?,?,?,?,?,?)",
                  (emp[0], emp[1], emp[2], emp[3], emp[4], hash_password(emp[5]), time.time()))

    if c.execute("SELECT COUNT(*) FROM training_courses").fetchone()[0] == 0:
        c.execute("INSERT INTO training_courses(title,description,department) VALUES (?,?,?)",
                  ("Cybersecurity Awareness", "Security fundamentals and safe corporate computing.", None))
        c.execute("INSERT INTO training_courses(title,description,department) VALUES (?,?,?)",
                  ("Enterprise Data Protection", "Data handling, access control and incident reporting.", None))
    if c.execute("SELECT COUNT(*) FROM announcements").fetchone()[0] == 0:
        c.execute("INSERT INTO announcements(department,title,message,created_at) VALUES (?,?,?,?)",
                  (None, "Welcome to Phoenix Shield Enterprise", "Enterprise Connect is now persistent. Records survive refresh and can be modified by authorized employees.", time.time()))
    conn.commit(); conn.close()

init_db()

# ---------------- SECURITY / TRAFFIC MONITOR ----------------
@app.middleware("http")
async def monitor_traffic(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    path = request.url.path
    method = request.method
    threat_level = "Safe"
    suspicious_keywords = ["select", "union", "<script>", "drop", "admin--", "' or '1'='1"]
    if detect_payload_anomaly(path) or any(kw in path.lower() for kw in suspicious_keywords):
        threat_level = "High (Hacker Detected!)"
    try:
        response = await call_next(request)
        status = str(response.status_code)
    except Exception:
        status = "500"
        raise
    if not path.startswith("/docs") and not path.startswith("/openapi.json"):
        conn = db(); conn.execute("INSERT INTO traffic_logs(ip_address,endpoint,method,status,threat_level,timestamp) VALUES(?,?,?,?,?,?)",
                                  (client_ip,path,method,status,threat_level,time.time())); conn.commit(); conn.close()
    return response

# ---------------- OLD PRIVATE DRIVE MODELS ----------------
class UserCredentials(BaseModel):
    username: str
    password: str
    phone: Optional[str] = None
    dob: Optional[str] = None
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
        with open(file_path, "r", encoding="utf-8") as f: return f.read()
    return "<h3>index.html not found</h3>"

@app.post("/api/private/register")
def register_user(creds: UserCredentials):
    conn=db()
    try:
        conn.execute("INSERT INTO users(username,password,phone,dob,is_verified) VALUES(?,?,?,?,0)", (creds.username,creds.password,creds.phone,creds.dob)); conn.commit()
    except sqlite3.IntegrityError:
        conn.close(); raise HTTPException(400,"Username already exists!")
    conn.close(); return {"message":"Account created successfully! Verification email dispatched to corporate inbox."}

@app.post("/api/private/login")
def login_user(creds: UserCredentials):
    conn=db(); user=conn.execute("SELECT username,phone,dob,is_verified FROM users WHERE username=? AND password=?",(creds.username,creds.password)).fetchone(); conn.close()
    if user: return {"message":"Login successful","username":user["username"],"phone":user["phone"] or "+91 9876543210","dob":user["dob"] or "11/02/2004","is_verified":user["is_verified"]}
    raise HTTPException(401,"Invalid credentials!")

@app.post("/api/private/upload")
def upload_user_data(file: UploadFile=File(...), username: str=Form(...), folder_name: str=Form("None")):
    safe_name=os.path.basename(file.filename); file_path=os.path.join(UPLOAD_DIR,safe_name)
    with open(file_path,"wb") as buffer: shutil.copyfileobj(file.file,buffer)
    size_bytes=os.path.getsize(file_path); size_mb=round(size_bytes/(1024*1024),2); size_str=f"{round(size_bytes/1024,2)} KB" if size_mb<0.1 else f"{size_mb} MB"
    mime_type,_=mimetypes.guess_type(safe_name); file_type="document"
    if mime_type:
        if mime_type.startswith("image/"): file_type="image"
        elif mime_type.startswith("video/"): file_type="video"
    conn=db(); conn.execute("INSERT INTO files(filename,username,folder_name,file_type,size_str) VALUES(?,?,?,?,?)",(safe_name,username,folder_name,file_type,size_str)); conn.commit(); conn.close()
    return {"filename":safe_name,"message":"Uploaded & Secured!"}

@app.get("/download/{filename}")
def download_file(filename:str):
    path=os.path.join(UPLOAD_DIR,os.path.basename(filename))
    if os.path.exists(path): return FileResponse(path,media_type="application/octet-stream",filename=os.path.basename(filename))
    raise HTTPException(404,"File not found")
@app.get("/uploads/{filename}")
def view_file(filename:str):
    path=os.path.join(UPLOAD_DIR,os.path.basename(filename))
    if os.path.exists(path): return FileResponse(path)
    raise HTTPException(404,"File not found")
@app.get("/api/private/files/{username}")
def list_files(username:str):
    conn=db(); rows=conn.execute("SELECT filename,folder_name,file_type,size_str FROM files WHERE username=?",(username,)).fetchall(); conn.close()
    return [{"filename":r["filename"],"folder_name":r["folder_name"],"file_type":r["file_type"],"size":r["size_str"]} for r in rows]
@app.delete("/api/private/files/{username}/{filename}")
def delete_file(username:str,filename:str):
    conn=db(); row=conn.execute("SELECT size_str FROM files WHERE username=? AND filename=?",(username,filename)).fetchone()
    if row:
        conn.execute("INSERT INTO trash_files(filename,username,size_str) VALUES(?,?,?)",(filename,username,row["size_str"])); conn.execute("DELETE FROM files WHERE username=? AND filename=?",(username,filename)); conn.commit()
    conn.close(); return {"message":"Moved to Trash"}
@app.get("/api/private/trash/{username}")
def get_trash_files(username:str):
    conn=db(); rows=conn.execute("SELECT filename,size_str FROM trash_files WHERE username=?",(username,)).fetchall(); conn.close(); return [{"filename":r["filename"],"size":r["size_str"]} for r in rows]
@app.post("/api/private/folders")
def create_folder(folder:FolderCreate):
    conn=db(); conn.execute("INSERT INTO folders(name,username) VALUES(?,?)",(folder.name,folder.username)); conn.commit(); conn.close(); return {"message":f"Folder '{folder.name}' created!"}
@app.get("/api/private/folders/{username}")
def list_folders(username:str):
    conn=db(); rows=conn.execute("SELECT name FROM folders WHERE username=?",(username,)).fetchall(); conn.close(); return [r["name"] for r in rows]
@app.delete("/api/private/folders/{username}/{foldername}")
def delete_folder(username:str,foldername:str):
    conn=db(); conn.execute("DELETE FROM folders WHERE username=? AND name=?",(username,foldername)); conn.execute("DELETE FROM files WHERE username=? AND folder_name=?",(username,foldername)); conn.commit(); conn.close(); return {"message":"Folder deleted successfully"}

# ---------------- OLD ENTERPRISE QUERY / KEY ----------------
@app.post("/api/enterprise/verify-key")
def verify_enterprise_key(payload:dict):
    key=payload.get("key"); valid=["MNC-SECURE-KEY-2026-X99","ENTERPRISE-PRO-KEY"]
    if key not in valid: raise HTTPException(403,"Invalid corporate license key.")
    return {"status":"authorized"}
@app.post("/api/enterprise/query")
def raise_department_query(q:QueryCreate):
    conn=db(); conn.execute("INSERT INTO dept_queries(from_dept,to_dept,query_text,status) VALUES(?,?,?,?)",(q.from_dept,q.to_dept,q.query_text,"Pending")); conn.commit(); conn.close(); return {"message":"Query raised successfully!"}
@app.get("/api/enterprise/queries/{dept}")
def get_department_queries(dept:str):
    conn=db(); rows=conn.execute("SELECT id,from_dept,query_text,status FROM dept_queries WHERE to_dept=?",(dept,)).fetchall(); conn.close(); return [dict(r) for r in rows]

# ---------------- ENTERPRISE AUTH / HELPERS ----------------
class EnterpriseLogin(BaseModel):
    employee_id:str; password:str; department:str
class EmployeeCreate(BaseModel):
    employee_id:str; name:str; department:str; role:str="Employee"; email:Optional[str]=None; password:str="ChangeMe@123"
class TicketCreate(BaseModel):
    category:str; subject:str; description:str; priority:str="Medium"
class TicketUpdate(BaseModel):
    status:Optional[str]=None; priority:Optional[str]=None; resolution:Optional[str]=None
class MeetingCreate(BaseModel):
    title:str; meeting_date:str; meeting_time:str; description:Optional[str]=""; attendees:list[str]=[]
class MeetingUpdate(BaseModel):
    title:Optional[str]=None; meeting_date:Optional[str]=None; meeting_time:Optional[str]=None; description:Optional[str]=None; status:Optional[str]=None
class AttendanceAction(BaseModel):
    action:str
class LeaveCreate(BaseModel):
    leave_type:str; start_date:str; end_date:str; reason:Optional[str]=""
class LeaveUpdate(BaseModel):
    status:str
class TaskCreate(BaseModel):
    title:str; description:Optional[str]=""; assigned_to:str; priority:str="Medium"; due_date:Optional[str]=""
class TaskUpdate(BaseModel):
    status:Optional[str]=None; title:Optional[str]=None; priority:Optional[str]=None; due_date:Optional[str]=None
class ProjectCreate(BaseModel):
    name:str; description:Optional[str]=""; progress:int=0
class ProjectUpdate(BaseModel):
    name:Optional[str]=None; description:Optional[str]=None; progress:Optional[int]=None
class MessageCreate(BaseModel):
    message:str
class KPIUpdate(BaseModel):
    title:str; target:Optional[str]=""; progress:int=0; review_note:Optional[str]=""

DEPARTMENTS=["Cybersecurity","Human Resources (HR)","Finance & Accounts","Sales","Information Technology (IT)"]

def get_emp(employee_id):
    conn=db(); e=conn.execute("SELECT * FROM employees WHERE employee_id=?",(employee_id,)).fetchone(); conn.close(); return e

def audit(employee_id,action,entity,entity_id=None,details=""):
    conn=db(); conn.execute("INSERT INTO audit_logs(employee_id,action,entity,entity_id,details,created_at) VALUES(?,?,?,?,?,?)",(employee_id,action,entity,str(entity_id) if entity_id is not None else None,details,time.time())); conn.commit(); conn.close()

def notify(employee_id,title,message):
    conn=db(); conn.execute("INSERT INTO notifications(employee_id,title,message,created_at) VALUES(?,?,?,?)",(employee_id,title,message,time.time())); conn.commit(); conn.close()

def authorized(actor_id, owner_id, admin=False):
    actor=get_emp(actor_id); owner=get_emp(owner_id)
    if not actor or not owner: return False
    if actor_id==owner_id: return True
    return admin and actor["role"] in ("Department Admin","Super Admin") and actor["department"]==owner["department"]

@app.post("/api/enterprise/login")
def enterprise_login(payload:EnterpriseLogin):
    e=get_emp(payload.employee_id)
    if not e or e["department"]!=payload.department or e["password_hash"]!=hash_password(payload.password): raise HTTPException(401,"Invalid employee ID, password, or department.")
    audit(e["employee_id"],"LOGIN","session",None,"Enterprise login")
    return {"authenticated":True,"employee":dict(e, password_hash=None)}

@app.get("/api/enterprise/me/{employee_id}")
def enterprise_me(employee_id:str):
    e=get_emp(employee_id)
    if not e: raise HTTPException(404,"Employee not found")
    return {"employee":dict(e, password_hash=None)}

@app.get("/api/enterprise/employees")
def employees(department:Optional[str]=None):
    conn=db(); rows=conn.execute("SELECT employee_id,name,department,role,email,created_at FROM employees" + (" WHERE department=?" if department else "") + " ORDER BY name", ((department,) if department else ())).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.post("/api/enterprise/employees")
def create_employee(payload:EmployeeCreate, actor_id:str):
    actor=get_emp(actor_id)
    if not actor or actor["role"] not in ("Department Admin","Super Admin"): raise HTTPException(403,"Admin permission required")
    if actor["role"]!="Super Admin" and actor["department"]!=payload.department: raise HTTPException(403,"You can only manage your department")
    conn=db()
    try:
        conn.execute("INSERT INTO employees(employee_id,name,department,role,email,password_hash,created_at) VALUES(?,?,?,?,?,?,?)",(payload.employee_id,payload.name,payload.department,payload.role,payload.email,hash_password(payload.password),time.time())); conn.commit()
    except sqlite3.IntegrityError: conn.close(); raise HTTPException(400,"Employee ID already exists")
    conn.close(); audit(actor_id,"CREATE","employee",payload.employee_id,payload.name); return {"message":"Employee created"}

# ---------------- ATTENDANCE ----------------
@app.post("/api/enterprise/attendance/{employee_id}")
def attendance_action(employee_id:str,payload:AttendanceAction):
    if not get_emp(employee_id): raise HTTPException(404,"Employee not found")
    today=time.strftime("%Y-%m-%d"); now=time.strftime("%Y-%m-%d %H:%M:%S"); conn=db(); row=conn.execute("SELECT * FROM attendance WHERE employee_id=? AND work_date=?",(employee_id,today)).fetchone()
    if payload.action=="check-in":
        if row: raise HTTPException(400,"Already checked in today")
        conn.execute("INSERT INTO attendance(employee_id,work_date,check_in,status) VALUES(?,?,?,?)",(employee_id,today,now,"Present"))
    elif payload.action=="check-out":
        if not row or not row["check_in"]: raise HTTPException(400,"Check in first")
        if row["check_out"]: raise HTTPException(400,"Already checked out today")
        conn.execute("UPDATE attendance SET check_out=? WHERE id=?",(now,row["id"]))
    else: raise HTTPException(400,"Invalid attendance action")
    conn.commit(); conn.close(); audit(employee_id,payload.action.upper(),"attendance",today); return {"message":payload.action.replace("-"," ").title()+" successful"}
@app.get("/api/enterprise/attendance/{employee_id}")
def attendance_history(employee_id:str):
    conn=db(); rows=conn.execute("SELECT * FROM attendance WHERE employee_id=? ORDER BY work_date DESC LIMIT 100",(employee_id,)).fetchall(); conn.close(); return [dict(r) for r in rows]

# ---------------- LEAVE ----------------
@app.post("/api/enterprise/leave/{employee_id}")
def apply_leave(employee_id:str,payload:LeaveCreate):
    now=time.time(); conn=db(); cur=conn.execute("INSERT INTO leave_requests(employee_id,leave_type,start_date,end_date,reason,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(employee_id,payload.leave_type,payload.start_date,payload.end_date,payload.reason,now,now)); lid=cur.lastrowid; conn.commit(); conn.close(); audit(employee_id,"CREATE","leave",lid); return {"id":lid,"message":"Leave request submitted"}
@app.get("/api/enterprise/leave/{employee_id}")
def leave_history(employee_id:str):
    conn=db(); rows=conn.execute("SELECT * FROM leave_requests WHERE employee_id=? ORDER BY id DESC",(employee_id,)).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.patch("/api/enterprise/leave/{leave_id}")
def update_leave(leave_id:int,payload:LeaveUpdate,actor_id:str):
    conn=db(); row=conn.execute("SELECT * FROM leave_requests WHERE id=?",(leave_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404,"Leave request not found")
    actor=get_emp(actor_id); owner=get_emp(row["employee_id"])
    if not actor or not owner: raise HTTPException(404,"Employee not found")
    if actor_id!=row["employee_id"] and not (actor["role"] in ("Department Admin","Super Admin") and actor["department"]==owner["department"]): raise HTTPException(403,"Not authorized")
    conn=db(); conn.execute("UPDATE leave_requests SET status=?,updated_at=? WHERE id=?",(payload.status,time.time(),leave_id)); conn.commit(); conn.close(); notify(row["employee_id"],"Leave updated",f"Your leave request #{leave_id} is now {payload.status}."); audit(actor_id,"UPDATE","leave",leave_id,payload.status); return {"message":"Leave updated"}

# ---------------- TASKS ----------------
@app.post("/api/enterprise/tasks")
def create_task(payload:TaskCreate,actor_id:str):
    if not get_emp(actor_id) or not get_emp(payload.assigned_to): raise HTTPException(404,"Employee not found")
    now=time.time(); conn=db(); cur=conn.execute("INSERT INTO tasks(owner_employee_id,assigned_to,title,description,priority,due_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",(actor_id,payload.assigned_to,payload.title,payload.description,payload.priority,payload.due_date,now,now)); tid=cur.lastrowid; conn.commit(); conn.close(); notify(payload.assigned_to,"New task",payload.title); audit(actor_id,"CREATE","task",tid,payload.title); return {"id":tid,"message":"Task created"}
@app.get("/api/enterprise/tasks/{employee_id}")
def list_tasks(employee_id:str):
    conn=db(); rows=conn.execute("SELECT * FROM tasks WHERE owner_employee_id=? OR assigned_to=? ORDER BY id DESC",(employee_id,employee_id)).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.patch("/api/enterprise/tasks/{task_id}")
def update_task(task_id:int,payload:TaskUpdate,actor_id:str):
    conn=db(); row=conn.execute("SELECT * FROM tasks WHERE id=?",(task_id,)).fetchone(); conn.close()
    if not row or not authorized(actor_id,row["owner_employee_id"],True) and actor_id!=row["assigned_to"]: raise HTTPException(403,"Not authorized")
    fields=[]; vals=[]
    for k in ("status","title","priority","due_date"):
        v=getattr(payload,k)
        if v is not None: fields.append(k+"=?"); vals.append(v)
    if not fields: return {"message":"Nothing to update"}
    vals += [time.time(),task_id]; conn=db(); conn.execute("UPDATE tasks SET "+",".join(fields)+",updated_at=? WHERE id=?",vals); conn.commit(); conn.close(); audit(actor_id,"UPDATE","task",task_id); return {"message":"Task updated"}

# ---------------- PROJECTS ----------------
@app.post("/api/enterprise/projects")
def create_project(payload:ProjectCreate,actor_id:str):
    now=time.time(); conn=db(); cur=conn.execute("INSERT INTO projects(owner_employee_id,name,description,progress,created_at,updated_at) VALUES(?,?,?,?,?,?)",(actor_id,payload.name,payload.description,max(0,min(100,payload.progress)),now,now)); pid=cur.lastrowid; conn.commit(); conn.close(); audit(actor_id,"CREATE","project",pid,payload.name); return {"id":pid,"message":"Project created"}
@app.get("/api/enterprise/projects/{employee_id}")
def list_projects(employee_id:str):
    e=get_emp(employee_id); conn=db(); rows=conn.execute("SELECT * FROM projects WHERE owner_employee_id=? OR owner_employee_id IN (SELECT employee_id FROM employees WHERE department=?) ORDER BY id DESC",(employee_id,e["department"] if e else "")).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.patch("/api/enterprise/projects/{project_id}")
def update_project(project_id:int,payload:ProjectUpdate,actor_id:str):
    conn=db(); row=conn.execute("SELECT * FROM projects WHERE id=?",(project_id,)).fetchone(); conn.close()
    if not row or not authorized(actor_id,row["owner_employee_id"],True): raise HTTPException(403,"Not authorized")
    fields=[]; vals=[]
    for k in ("name","description","progress"):
        v=getattr(payload,k)
        if v is not None: fields.append(k+"=?"); vals.append(max(0,min(100,v)) if k=="progress" else v)
    if fields:
        vals += [time.time(),project_id]; conn=db(); conn.execute("UPDATE projects SET "+",".join(fields)+",updated_at=? WHERE id=?",vals); conn.commit(); conn.close()
    audit(actor_id,"UPDATE","project",project_id); return {"message":"Project updated"}

# ---------------- COMMUNICATION ----------------
@app.post("/api/enterprise/messages/{employee_id}")
def send_message(employee_id:str,payload:MessageCreate):
    e=get_emp(employee_id); conn=db(); cur=conn.execute("INSERT INTO messages(sender_employee_id,department,message,created_at) VALUES(?,?,?,?)",(employee_id,e["department"],payload.message,time.time())); mid=cur.lastrowid; conn.commit(); conn.close(); audit(employee_id,"CREATE","message",mid); return {"id":mid,"message":"Message posted"}
@app.get("/api/enterprise/messages/{employee_id}")
def messages(employee_id:str):
    e=get_emp(employee_id); conn=db(); rows=conn.execute("SELECT * FROM messages WHERE department=? ORDER BY id DESC LIMIT 100",(e["department"],)).fetchall(); conn.close(); return [dict(r) for r in rows]

# ---------------- MEETINGS ----------------
@app.post("/api/enterprise/meetings/{employee_id}")
def create_meeting(employee_id:str,payload:MeetingCreate):
    now=time.time(); conn=db(); cur=conn.execute("INSERT INTO meetings(organizer_employee_id,title,meeting_date,meeting_time,description,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",(employee_id,payload.title,payload.meeting_date,payload.meeting_time,payload.description,now,now)); mid=cur.lastrowid
    conn.execute("INSERT OR IGNORE INTO meeting_attendees(meeting_id,employee_id) VALUES(?,?)",(mid,employee_id))
    for attendee in payload.attendees:
        if get_emp(attendee): conn.execute("INSERT OR IGNORE INTO meeting_attendees(meeting_id,employee_id) VALUES(?,?)",(mid,attendee)); notify(attendee,"Meeting invitation",payload.title)
    conn.commit(); conn.close(); audit(employee_id,"CREATE","meeting",mid,payload.title); return {"id":mid,"message":"Meeting scheduled"}
@app.get("/api/enterprise/meetings/{employee_id}")
def list_meetings(employee_id:str):
    conn=db(); rows=conn.execute("SELECT m.*,GROUP_CONCAT(a.employee_id) attendees FROM meetings m LEFT JOIN meeting_attendees a ON a.meeting_id=m.id WHERE m.organizer_employee_id=? OR m.id IN (SELECT meeting_id FROM meeting_attendees WHERE employee_id=?) GROUP BY m.id ORDER BY m.meeting_date,m.meeting_time",(employee_id,employee_id)).fetchall(); conn.close(); out=[]
    for r in rows:
        d=dict(r); d["attendees"]=(r["attendees"] or "").split(",") if r["attendees"] else []; out.append(d)
    return out
@app.patch("/api/enterprise/meetings/{meeting_id}")
def update_meeting(meeting_id:int,payload:MeetingUpdate,actor_id:str):
    conn=db(); row=conn.execute("SELECT * FROM meetings WHERE id=?",(meeting_id,)).fetchone(); conn.close()
    if not row or not authorized(actor_id,row["organizer_employee_id"],False): raise HTTPException(403,"Only the meeting organizer can modify this meeting")
    fields=[]; vals=[]
    for k in ("title","meeting_date","meeting_time","description","status"):
        v=getattr(payload,k)
        if v is not None: fields.append(k+"=?"); vals.append(v)
    if fields:
        vals += [time.time(),meeting_id]; conn=db(); conn.execute("UPDATE meetings SET "+",".join(fields)+",updated_at=? WHERE id=?",vals); conn.commit(); conn.close()
    audit(actor_id,"UPDATE","meeting",meeting_id,payload.status or "rescheduled"); return {"message":"Meeting updated"}

# ---------------- TICKETS ----------------
@app.post("/api/enterprise/tickets/{employee_id}")
def create_ticket(employee_id:str,payload:TicketCreate):
    e=get_emp(employee_id); ticket_no=f"PS-{time.strftime('%Y%m%d')}-{int(time.time()*1000)%100000:05d}"; now=time.time(); conn=db(); cur=conn.execute("INSERT INTO tickets(ticket_no,employee_id,department,category,subject,description,priority,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",(ticket_no,employee_id,e["department"],payload.category,payload.subject,payload.description,payload.priority,now,now)); tid=cur.lastrowid; conn.commit(); conn.close(); audit(employee_id,"CREATE","ticket",tid,ticket_no); notify(employee_id,"Ticket created",f"{ticket_no}: {payload.subject}"); return {"id":tid,"ticket_no":ticket_no,"message":"Ticket raised successfully"}
@app.get("/api/enterprise/tickets/{employee_id}")
def list_tickets(employee_id:str):
    e=get_emp(employee_id); conn=db(); rows=conn.execute("SELECT * FROM tickets WHERE employee_id=? OR (department=? AND ? IN (SELECT employee_id FROM employees WHERE employee_id=? AND role IN ('Department Admin','Super Admin'))) ORDER BY id DESC",(employee_id,e["department"],employee_id,employee_id)).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.patch("/api/enterprise/tickets/{ticket_id}")
def update_ticket(ticket_id:int,payload:TicketUpdate,actor_id:str):
    conn=db(); row=conn.execute("SELECT * FROM tickets WHERE id=?",(ticket_id,)).fetchone(); conn.close()
    if not row: raise HTTPException(404,"Ticket not found")
    actor=get_emp(actor_id); owner=get_emp(row["employee_id"])
    allowed=actor_id==row["employee_id"] or (actor and owner and actor["role"] in ("Department Admin","Super Admin") and actor["department"]==owner["department"])
    if not allowed: raise HTTPException(403,"Not authorized")
    fields=[]; vals=[]
    for k in ("status","priority","resolution"):
        v=getattr(payload,k)
        if v is not None: fields.append(k+"=?"); vals.append(v)
    if fields:
        vals += [time.time(),ticket_id]; conn=db(); conn.execute("UPDATE tickets SET "+",".join(fields)+",updated_at=? WHERE id=?",vals); conn.commit(); conn.close()
    audit(actor_id,"UPDATE","ticket",ticket_id,payload.status or "modified"); notify(row["employee_id"],"Ticket updated",f"Ticket {row['ticket_no']} was updated."); return {"message":"Ticket updated"}

# ---------------- NOTIFICATIONS / AUDIT ----------------
@app.get("/api/enterprise/notifications/{employee_id}")
def get_notifications(employee_id:str):
    conn=db(); rows=conn.execute("SELECT * FROM notifications WHERE employee_id=? ORDER BY id DESC LIMIT 100",(employee_id,)).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.patch("/api/enterprise/notifications/{notification_id}")
def read_notification(notification_id:int,employee_id:str):
    conn=db(); conn.execute("UPDATE notifications SET is_read=1 WHERE id=? AND employee_id=?",(notification_id,employee_id)); conn.commit(); conn.close(); return {"message":"Notification marked read"}
@app.get("/api/enterprise/audit/{employee_id}")
def get_audit(employee_id:str):
    e=get_emp(employee_id); conn=db()
    if e and e["role"] in ("Department Admin","Super Admin"): rows=conn.execute("SELECT * FROM audit_logs WHERE employee_id IN (SELECT employee_id FROM employees WHERE department=?) ORDER BY id DESC LIMIT 200",(e["department"],)).fetchall()
    else: rows=conn.execute("SELECT * FROM audit_logs WHERE employee_id=? ORDER BY id DESC LIMIT 100",(employee_id,)).fetchall()
    conn.close(); return [dict(r) for r in rows]

# ---------------- DASHBOARD / PAYROLL / TRAINING / KPI / DOCUMENTS ----------------
@app.get("/api/enterprise/dashboard/{employee_id}")
def dashboard(employee_id:str):
    e=get_emp(employee_id)
    if not e: raise HTTPException(404,"Employee not found")
    conn=db(); dep=e["department"]
    counts={
        "employees":conn.execute("SELECT COUNT(*) n FROM employees WHERE department=?",(dep,)).fetchone()["n"],
        "open_tickets":conn.execute("SELECT COUNT(*) n FROM tickets WHERE department=? AND status NOT IN ('Closed','Resolved')",(dep,)).fetchone()["n"],
        "pending_leave":conn.execute("SELECT COUNT(*) n FROM leave_requests WHERE employee_id IN (SELECT employee_id FROM employees WHERE department=?) AND status='Pending'",(dep,)).fetchone()["n"],
        "active_tasks":conn.execute("SELECT COUNT(*) n FROM tasks WHERE (owner_employee_id IN (SELECT employee_id FROM employees WHERE department=? ) OR assigned_to IN (SELECT employee_id FROM employees WHERE department=?)) AND status!='Done'",(dep,dep)).fetchone()["n"],
        "meetings":conn.execute("SELECT COUNT(*) n FROM meetings WHERE organizer_employee_id IN (SELECT employee_id FROM employees WHERE department=?) AND status='Scheduled'",(dep,)).fetchone()["n"]
    }
    anns=conn.execute("SELECT * FROM announcements WHERE department IS NULL OR department=? ORDER BY id DESC LIMIT 10",(dep,)).fetchall(); conn.close(); return {"counts":counts,"announcements":[dict(a) for a in anns]}
@app.get("/api/enterprise/payroll/{employee_id}")
def payroll(employee_id:str):
    conn=db(); rows=conn.execute("SELECT * FROM payroll WHERE employee_id=? ORDER BY id DESC",(employee_id,)).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.get("/api/enterprise/training/{employee_id}")
def training(employee_id:str):
    conn=db(); rows=conn.execute("SELECT c.id,c.title,c.description,c.department,COALESCE(e.progress,0) progress,COALESCE(e.status,'Not Started') status FROM training_courses c LEFT JOIN training_enrollments e ON c.id=e.course_id AND e.employee_id=? ORDER BY c.id",(employee_id,)).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.patch("/api/enterprise/training/{course_id}")
def update_training(course_id:int,employee_id:str,progress:int):
    progress=max(0,min(100,progress)); status="Completed" if progress==100 else "In Progress"; conn=db(); conn.execute("INSERT INTO training_enrollments(course_id,employee_id,progress,status) VALUES(?,?,?,?) ON CONFLICT(course_id,employee_id) DO UPDATE SET progress=excluded.progress,status=excluded.status",(course_id,employee_id,progress,status)); conn.commit(); conn.close(); audit(employee_id,"UPDATE","training",course_id,str(progress)); return {"message":"Training progress saved"}
@app.get("/api/enterprise/kpi/{employee_id}")
def kpis(employee_id:str):
    conn=db(); rows=conn.execute("SELECT * FROM kpi_goals WHERE employee_id=? ORDER BY id DESC",(employee_id,)).fetchall(); conn.close(); return [dict(r) for r in rows]
@app.post("/api/enterprise/kpi/{employee_id}")
def create_kpi(employee_id:str,payload:KPIUpdate):
    now=time.time(); conn=db(); cur=conn.execute("INSERT INTO kpi_goals(employee_id,title,target,progress,review_note,updated_at) VALUES(?,?,?,?,?,?)",(employee_id,payload.title,payload.target,max(0,min(100,payload.progress)),payload.review_note,now)); kid=cur.lastrowid; conn.commit(); conn.close(); audit(employee_id,"CREATE","kpi",kid,payload.title); return {"id":kid,"message":"KPI saved"}
@app.get("/api/enterprise/documents/{employee_id}")
def documents(employee_id:str):
    conn=db(); rows=conn.execute("SELECT * FROM corporate_documents WHERE employee_id=? ORDER BY id DESC",(employee_id,)).fetchall(); conn.close(); return [dict(r) for r in rows]

# ---------------- SECURITY LOGS (OLD) ----------------
@app.get("/api/security/traffic-logs")
def get_traffic_logs():
    conn=db(); rows=conn.execute("SELECT ip_address,endpoint,method,status,threat_level,timestamp FROM traffic_logs ORDER BY id DESC LIMIT 30").fetchall(); conn.close(); return [{"ip":r["ip_address"],"endpoint":r["endpoint"],"method":r["method"],"status":r["status"],"threat":r["threat_level"],"time":r["timestamp"]} for r in rows]
