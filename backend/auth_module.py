import json
import bcrypt
from pathlib import Path
from fastapi import Request, HTTPException, Response, Form
from fastapi.routing import APIRouter
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from itsdangerous import URLSafeSerializer

router = APIRouter()

# Configuration
SECRET_KEY = "super-secret-key"
COOKIE_NAME = "session_id"
serializer = URLSafeSerializer(SECRET_KEY)
USERS_FILE = Path("backend/users/users_db.json")

# Utilities
def load_users():
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    return []

def save_users(users):
    USERS_FILE.write_text(json.dumps(users, indent=2))

def get_user(username):
    users = load_users()
    return next((u for u in users if u["username"] == username), None)

def user_navbar(user):
    return f"""
    <div class="navbar">
        <span>👤 {user['username']} ({user['role']})</span>
        <a href="/logout"><button>Logout</button></a>
    </div>
    """

# Login Page
@router.get("/login", response_class=HTMLResponse)
async def login_form():
    return HTMLResponse("""
    <html>
    <head>
      <link rel="stylesheet" href="/ui/css/auth.css">
    </head>
    <body>
      <form action="/login" method="post">
        <h2>Login</h2>
        <input name="username" placeholder="Username" required><br>
        <input name="password" type="password" placeholder="Password" required><br>
        <button type="submit">Login</button>
        <a href="/register"><button type="button">Create Account</button></a>
      </form>
    </body>
    </html>
    """)

@router.post("/login")
async def login(response: Response, username: str = Form(...), password: str = Form(...)):
    user = get_user(username)
    if not user or not bcrypt.checkpw(password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    session_token = serializer.dumps({"username": username})
    response = RedirectResponse(url="/ui", status_code=302)
    response.set_cookie(COOKIE_NAME, session_token, httponly=True)
    return response

# Registration
@router.get("/register", response_class=HTMLResponse)
async def register_form():
    return HTMLResponse("""
    <html>
    <head>
      <link rel="stylesheet" href="/ui/css/auth.css">
    </head>
    <body>
      <form action="/register" method="post">
        <h2>Register</h2>
        <input name="username" placeholder="Username" required><br>
        <input name="password" type="password" placeholder="Password" required><br>
        <select name="role" required>
          <option value="operator">Operator</option>
          <option value="admin">Administrator</option>
        </select><br>
        <button type="submit">Register</button>
        <a href="/login"><button type="button">Back to Login</button></a>
      </form>
    </body>
    </html>
    """)

@router.post("/register")
async def register(response: Response, username: str = Form(...), password: str = Form(...), role: str = Form(...)):
    if get_user(username):
        raise HTTPException(status_code=400, detail="User already exists")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users = load_users()
    users.append({"username": username, "password": hashed, "role": role})
    save_users(users)
    response = RedirectResponse(url="/login", status_code=302)
    return response

# Logout
@router.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response

# Authenticated user info
@router.get("/api/me")
async def get_logged_user(request: Request):
    user = request.state.user
    if not user:
        return JSONResponse({"error": "unauthenticated"}, status_code=401)
    return {
        "username": user["username"],
        "role": user["role"]
    }

# Middleware for route protection
class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get(COOKIE_NAME)
        user = None
        if token:
            try:
                data = serializer.loads(token)
                user = get_user(data["username"])
            except:
                pass

        request.state.user = user

        path = request.url.path
        public_paths = ["/login", "/register", "/ui", "/logout"]

        # Protects routes that are not public
        if not user and not any(path.startswith(p) for p in public_paths):
            return RedirectResponse(url="/login")

        return await call_next(request)
