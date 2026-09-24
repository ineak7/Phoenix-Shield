from fastapi import APIRouter, HTTPException, status, UploadFile, File
from pydantic import BaseModel
import shutil
import os
import sqlite3

router = APIRouter()
UPLOAD_DIR = "app/uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

DB_FILE = "app/users.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT
        )
    ''')
    # Ensure default user always exists with correct credentials
    cursor.execute("INSERT OR REPLACE INTO users (username, password) VALUES (?, ?)", ("NitinMor", "Nitin@1234"))
    conn.commit()
    conn.close()

init_db()

class UserCredentials(BaseModel):
    username: str
    password: str

@router.post("/register")
def register_user(creds: UserCredentials):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (creds.username, creds.password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Username pehle se exist karta hai!")
    conn.close()
    return {"message": "Account successfully create ho gaya!"}

@router.post("/login")
def login_user(creds: UserCredentials):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (creds.username, creds.password))
    user = cursor.fetchone()
    conn.close()
    if user:
        return {"message": "Login successful", "username": creds.username}
    raise HTTPException(status_code=401, detail="Galat username ya password!")

@router.post("/upload")
def upload_user_data(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    return {"filename": file.filename, "message": "File successfully upload aur save ho gayi!"}

@router.get("/files")
def list_uploaded_files():
    if not os.path.exists(UPLOAD_DIR):
        return []
    files = []
    for filename in os.listdir(UPLOAD_DIR):
        file_path = os.path.join(UPLOAD_DIR, filename)
        if os.path.isfile(file_path):
            size_mb = round(os.path.getsize(file_path) / (1024 * 1024), 2)
            files.append({"filename": filename, "size": f"{size_mb} MB"})
    return files

@router.delete("/files/{filename}")
def delete_file(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        return {"message": "File delete ho gayi!"}
    raise HTTPException(status_code=404, detail="File nahi mili.")