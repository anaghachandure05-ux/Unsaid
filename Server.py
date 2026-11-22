#!/usr/bin/env python3
import http.server
import sqlite3
import hashlib
import hmac
import json
import uuid
import os
import re
from datetime import datetime
from urllib.parse import urlparse
from http.cookies import SimpleCookie

PORT = int(os.environ.get("PORT", 3000))
DB_PATH = "unsaid.db"
SECRET = b"unsaid-session-secret-change-me-in-production"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            content TEXT NOT NULL,
            is_from_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_user ON messages(user_id);
    """)
    cur = conn.execute("SELECT id FROM users WHERE is_admin = 1")
    if not cur.fetchone():
        admin_id = str(uuid.uuid4())
        pw_hash = hash_password("admin123")
        conn.execute(
            "INSERT INTO users (id, username, password_hash, is_admin) VALUES (?, ?, ?, 1)",
            (admin_id, "admin", pw_hash)
        )
        print('Admin created: username "admin" / password "admin123"')
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return salt.hex() + ":" + h.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, hash_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return hmac.compare_digest(h.hex(), hash_hex)
    except Exception:
        return False

def make_session(user_id: str, username: str, is_admin: bool) -> str:
    payload = f"{user_id}|{username}|{1 if is_admin else 0}|{int(datetime.utcnow().timestamp())}"
    sig = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    return payload + "|" + sig

def read_session(cookie_value: str):
    if not cookie_value:
        return None
    parts = cookie_value.split("|")
    if len(parts) != 5:
        return None
    user_id, username, is_admin_s, ts, sig = parts
    payload = f"{user_id}|{username}|{is_admin_s}|{ts}"
    expected = hmac.new(SECRET, payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return None
    if int(datetime.utcnow().timestamp()) - int(ts) > 7 * 24 * 3600:
        return None
    return {
        "user_id": user_id,
        "username": username,
        "is_admin": is_admin_s == "1"
    }

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {args[0]}")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, filename, content_type):
        path = os.path.join("public", filename)
        if not os.path.exists(path):
            self.send_error(404)
            return
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def get_session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        if "session" in cookie:
            return read_session(cookie["session"].value)
        return None

    def set_session_cookie(self, session_str):
        self.send_header(
            "Set-Cookie",
            f"session={session_str}; Path=/; HttpOnly; SameSite=Lax; Max-Age={7*24*3600}"
        )

    def clear_session_cookie(self):
        self.send_header("Set-Cookie", "session=; Path=/; Max-Age=0")

    def read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except Exception:
            return {}

    def do_GET(self):
        path = urlparse(self.path).path

        if path == "/":
            return self.send_file("index.html", "text/html; charset=utf-8")
        if path == "/app":
            return self.send_file("app.html", "text/html; charset=utf-8")
        if path == "/admin":
            return self.send_file("admin.html", "text/html; charset=utf-8")
        if path == "/styles.css":
            return self.send_file("styles.css", "text/css")
        if path == "/auth.js":
            return self.send_file("auth.js", "application/javascript")

        session = self.get_session()

        if path == "/api/me":
            if not session:
                return self.send_json({"loggedIn": False})
            return self.send_json({
                "loggedIn": True,
                "username": session["username"],
                "isAdmin": session["is_admin"]
            })

        if path == "/api/messages":
            if not session or session["is_admin"]:
                return self.send_json({"error": "Unauthorized"}, 401)
            conn = get_db()
            rows = conn.execute(
                "SELECT id, content, is_from_admin, created_at FROM messages WHERE user_id = ? ORDER BY created_at ASC",
                (session["user_id"],)
            ).fetchall()
            conn.close()
            return self.send_json({"messages": [dict(r) for r in rows]})

        if path == "/api/admin/users":
            if not session or not session["is_admin"]:
                return self.send_json({"error": "Admin only"}, 403)
            conn = get_db()
            rows = conn.execute("""
                SELECT u.id, u.username, u.created_at,
                       COUNT(m.id) as message_count,
                       MAX(m.created_at) as last_message
                FROM users u
                LEFT JOIN messages m ON u.id = m.user_id
                WHERE u.is_admin = 0
                GROUP BY u.id
                ORDER BY last_message DESC NULLS LAST
            """).fetchall()
            conn.close()
            return self.send_json({"users": [dict(r) for r in rows]})

        if path.startswith("/api/admin/messages/"):
            if not session or not session["is_admin"]:
                return self.send_json({"error": "Admin only"}, 403)
            user_id = path.rstrip("/").split("/")[-1]
            conn = get_db()
            user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
            rows = conn.execute(
                "SELECT id, content, is_from_admin, created_at FROM messages WHERE user_id = ? ORDER BY created_at ASC",
                (user_id,)
            ).fetchall()
            conn.close()
            return self.send_json({
                "messages": [dict(r) for r in rows],
                "username": user["username"] if user else "Unknown"
            })

        self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.read_body()
        session = self.get_session()

        if path == "/api/register":
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            if not username or not password:
                return self.send_json({"error": "Username and password required"}, 400)
            if len(username) < 3 or len(username) > 30:
                return self.send_json({"error": "Username must be 3-30 characters"}, 400)
            if len(password) < 6:
                return self.send_json({"error": "Password must be at least 6 characters"}, 400)
            if not re.match(r"^[a-zA-Z0-9_]+$", username):
                return self.send_json({"error": "Username can only contain letters, numbers, and underscores"}, 400)

            conn = get_db()
            try:
                user_id = str(uuid.uuid4())
                pw_hash = hash_password(password)
                conn.execute(
                    "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                    (user_id, username, pw_hash)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                conn.close()
                return self.send_json({"error": "Username already taken"}, 400)
            conn.close()

            sess = make_session(user_id, username, False)
            self.send_response(200)
            self.set_session_cookie(sess)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True, "username": username}).encode())
            return

        if path == "/api/login":
            username = (body.get("username") or "").strip()
            password = body.get("password") or ""
            if not username or not password:
                return self.send_json({"error": "Username and password required"}, 400)

            conn = get_db()
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            conn.close()
            if not user or not verify_password(password, user["password_hash"]):
                return self.send_json({"error": "Invalid username or password"}, 401)

            sess = make_session(user["id"], user["username"], bool(user["is_admin"]))
            self.send_response(200)
            self.set_session_cookie(sess)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "success": True,
                "username": user["username"],
                "isAdmin": bool(user["is_admin"])
            }).encode())
            return

        if path == "/api/logout":
            self.send_response(200)
            self.clear_session_cookie()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success":true}')
            return

        if path == "/api/messages":
            if not session or session["is_admin"]:
                return self.send_json({"error": "Please log in as a user"}, 401)
            content = (body.get("content") or "").strip()
            if not content:
                return self.send_json({"error": "Message cannot be empty"}, 400)
            if len(content) > 5000:
                return self.send_json({"error": "Message too long (max 5000 characters)"}, 400)

            msg_id = str(uuid.uuid4())
            conn = get_db()
            conn.execute(
                "INSERT INTO messages (id, user_id, content, is_from_admin) VALUES (?, ?, ?, 0)",
                (msg_id, session["user_id"], content)
            )
            conn.commit()
            conn.close()
            return self.send_json({"success": True, "id": msg_id})

        if path.startswith("/api/admin/messages/"):
            if not session or not session["is_admin"]:
                return self.send_json({"error": "Admin only"}, 403)
            user_id = path.rstrip("/").split("/")[-1]
            content = (body.get("content") or "").strip()
            if not content:
                return self.send_json({"error": "Reply cannot be empty"}, 400)
            if len(content) > 5000:
                return self.send_json({"error": "Reply too long"}, 400)

            conn = get_db()
            user = conn.execute("SELECT id FROM users WHERE id = ? AND is_admin = 0", (user_id,)).fetchone()
            if not user:
                conn.close()
                return self.send_json({"error": "User not found"}, 404)
            msg_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO messages (id, user_id, content, is_from_admin) VALUES (?, ?, ?, 1)",
                (msg_id, user_id, content)
            )
            conn.commit()
            conn.close()
            return self.send_json({"success": True, "id": msg_id})

        self.send_error(404)

if __name__ == "__main__":
    init_db()
    server = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"Unsaid is running at http://localhost:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
