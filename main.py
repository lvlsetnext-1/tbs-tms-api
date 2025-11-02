from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt, time
from typing import List, Optional

# --- Config ---
JWT_SECRET = "CHANGE_ME_SUPER_SECRET"  # set in Render ENV as well
JWT_ALG = "HS256"
ALLOWED_ORIGINS = [
    "http://YOUR-S3-WEBSITE-ENDPOINT",   # e.g. http://lvl-set-tms.s3-website.us-east-2.amazonaws.com
    "https://YOUR-CUSTOM-DOMAIN",        # if/when you add one
]

# --- App ---
app = FastAPI(title="TB&S TMS API", version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET","POST","PUT","DELETE","OPTIONS"],
    allow_headers=["Authorization","Content-Type"],
    expose_headers=["Content-Disposition"],
)

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory users to start (we’ll replace with Neon later)
# password for all = "test123"
USERS = {
    "admin@tbs.local": {"hash": pwd.hash("test123"), "role": "admin"},
    "dispatch@tbs.local": {"hash": pwd.hash("test123"), "role": "dispatcher"},
    "viewer@tbs.local": {"hash": pwd.hash("test123"), "role": "viewer"},
}

def make_token(email: str, role: str) -> str:
    now = int(time.time())
    payload = {"sub": email, "role": role, "iat": now, "exp": now + 60*60*8}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_token(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

def guard(*roles):
    def _wrap(clb):
        def _dep(authorization: Optional[str] = None):
            if not authorization or not authorization.lower().startswith("bearer "):
                raise HTTPException(status_code=401, detail="Missing token")
            claims = verify_token(authorization.split(" ",1)[1])
            if roles and claims.get("role") not in roles:
                raise HTTPException(status_code=403, detail="Forbidden")
            return claims
        return Depends(_dep)
    return _wrap

# ---- Models (lightweight for now) ----
class DriverIn(BaseModel):
    name: str
    licenseNo: Optional[str] = None
    phone: Optional[str] = None
    payRate: Optional[float] = 0.0

class DriverOut(DriverIn):
    id: str

# In-memory data so the UI works immediately
_DRIVERS = [
    {"id": "d1", "name": "Ava Johnson", "licenseNo": "GA-1234", "phone": "404-555-0101", "payRate": 0.62},
    {"id": "d2", "name": "Marcus Lee", "licenseNo": "GA-5678", "phone": "470-555-0147", "payRate": 0.65},
]

# ---- Routes ----
@app.get("/v1/health")
def health(): return {"ok": True, "service": "tbs-api"}

@app.post("/v1/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    email = form.username
    user = USERS.get(email)
    if not user or not pwd.verify(form.password, user["hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = make_token(email, user["role"])
    return {"accessToken": token, "role": user["role"]}

@app.get("/v1/drivers", response_model=List[DriverOut], dependencies=[guard("admin","dispatcher","viewer")])
def list_drivers():
    return _DRIVERS

@app.post("/v1/drivers", response_model=DriverOut, dependencies=[guard("admin","dispatcher")])
def create_driver(d: DriverIn):
    new = d.dict()
    new["id"] = f"d{len(_DRIVERS)+1}"
    _DRIVERS.append(new)
    return new

@app.delete("/v1/drivers/{driver_id}", dependencies=[guard("admin")])
def delete_driver(driver_id: str):
    global _DRIVERS
    before = len(_DRIVERS)
    _DRIVERS = [x for x in _DRIVERS if x["id"] != driver_id]
    if len(_DRIVERS) == before:
        raise HTTPException(status_code=404, detail="Not found")
    return {"ok": True}
