from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import List, Optional
import jwt
import time

# --- Config ---
JWT_SECRET = "transportationmanagementsystem"  # TODO: move to environment
JWT_ALG = "HS256"

ALLOWED_ORIGINS = [
    "http://lvl-set-tms.s3-website.us-east-2.amazonaws.com",
    "https://YOUR-CUSTOM-DOMAIN",
]

# --- FastAPI app ---
app = FastAPI(title="TB&S TMS API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
    expose_headers=["Content-Disposition"],
    max_age=86400,
)

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")

# In-memory users
USERS = {
    "admin@tbs.local": {
        "hash": pwd.hash("test123"),
        "role": "admin",
    },
    "dispatch@tbs.local": {
        "hash": pwd.hash("test123"),
        "role": "dispatcher",
    },
    "viewer@tbs.local": {
        "hash": pwd.hash("test123"),
        "role": "viewer",
    },
}

# --- JWT helpers ---

def make_token(email: str, role: str, ttl_seconds: int = 60 * 60 * 8) -> str:
    now = int(time.time())
    payload = {
        "sub": email,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

# --- Pydantic schemas ---

class LoginOut(BaseModel):
    accessToken: str
    role: str


class DriverBase(BaseModel):
    name: str
    phone: str
    email: Optional[str] = None
    status: str


class DriverIn(DriverBase):
    pass


class DriverOut(DriverBase):
    id: str


class LoadBase(BaseModel):
    reference: str
    customer: str
    origin: str
    destination: str
    pickup_date: str
    delivery_date: str
    driver_id: Optional[str] = None
    status: str


class LoadIn(LoadBase):
    pass


class LoadOut(LoadBase):
    id: str


class InvoiceBase(BaseModel):
    load_id: str
    amount: float
    status: str


class InvoiceIn(InvoiceBase):
    pass


class InvoiceOut(InvoiceBase):
    id: str


# --- Auth dependencies ---

def get_current_user(authorization: str = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing token",
        )
    token = authorization.split(" ", 1)[1]
    payload = decode_token(token)
    email = payload.get("sub")
    role = payload.get("role")
    if not email or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )
    return {"email": email, "role": role}


def guard(*allowed_roles: str):
    def dependency(user=Depends(get_current_user)):
        if user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return user

    return dependency


# --- Auth endpoint ---

@app.post("/v1/auth/login", response_model=LoginOut)
def login(form: OAuth2PasswordRequestForm = Depends()):
    email = form.username
    user = USERS.get(email)
    if not user or not pwd.verify(form.password, user["hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = make_token(email, user["role"])
    return {"accessToken": token, "role": user["role"]}


# --- In-memory data stores (seed data) ---

_DRIVERS = [
    {
        "id": "d1",
        "name": "John Doe",
        "phone": "555-1234",
        "email": "john@example.com",
        "status": "active",
    },
    {
        "id": "d2",
        "name": "Jane Smith",
        "phone": "555-5678",
        "email": "jane@example.com",
        "status": "inactive",
    },
]

_LOADS = [
    {
        "id": "l1",
        "reference": "REF-001",
        "customer": "Acme Corp",
        "origin": "Atlanta, GA",
        "destination": "Savannah, GA",
        "pickup_date": "2025-11-01",
        "delivery_date": "2025-11-02",
        "driver_id": "d1",
        "status": "scheduled",
    }
]

_INVOICES = [
    {
        "id": "i1",
        "load_id": "l1",
        "amount": 1200.0,
        "status": "unpaid",
    }
]


# --- Driver endpoints ---

@app.get(
    "/v1/drivers",
    response_model=List[DriverOut],
    dependencies=[Depends(guard("admin", "dispatcher", "viewer"))],
)
def list_drivers():
    return _DRIVERS


@app.post(
    "/v1/drivers",
    response_model=DriverOut,
    dependencies=[Depends(guard("admin", "dispatcher"))],
)
def create_driver(d: DriverIn):
    new = d.dict()
    new["id"] = f"d{len(_DRIVERS) + 1}"
    _DRIVERS.append(new)
    return new


@app.put(
    "/v1/drivers/{driver_id}",
    response_model=DriverOut,
    dependencies=[Depends(guard("admin", "dispatcher"))],
)
def update_driver(driver_id: str, d: DriverIn):
    for idx, drv in enumerate(_DRIVERS):
        if drv["id"] == driver_id:
            updated = drv.copy()
            updated.update(d.dict())
            _DRIVERS[idx] = updated
            return updated
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Driver not found",
    )


@app.delete(
    "/v1/drivers/{driver_id}",
    dependencies=[Depends(guard("admin"))],
)
def delete_driver(driver_id: str):
    global _DRIVERS
    before = len(_DRIVERS)
    _DRIVERS = [x for x in _DRIVERS if x["id"] != driver_id]
    if len(_DRIVERS) == before:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Driver not found",
        )
    return {"ok": True}


# --- Load endpoints ---

@app.get(
    "/v1/loads",
    response_model=List[LoadOut],
    dependencies=[Depends(guard("admin", "dispatcher", "viewer"))],
)
def list_loads():
    return _LOADS


@app.post(
    "/v1/loads",
    response_model=LoadOut,
    dependencies=[Depends(guard("admin", "dispatcher"))],
)
def create_load(l: LoadIn):
    new = l.dict()
    new["id"] = f"l{len(_LOADS) + 1}"
    _LOADS.append(new)
    return new


@app.put(
    "/v1/loads/{load_id}",
    response_model=LoadOut,
    dependencies=[Depends(guard("admin", "dispatcher"))],
)
def update_load(load_id: str, l: LoadIn):
    for idx, load in enumerate(_LOADS):
        if load["id"] == load_id:
            updated = load.copy()
            updated.update(l.dict())
            _LOADS[idx] = updated
            return updated
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Load not found",
    )


@app.delete(
    "/v1/loads/{load_id}",
    dependencies=[Depends(guard("admin"))],
)
def delete_load(load_id: str):
    global _LOADS
    before = len(_LOADS)
    _LOADS = [x for x in _LOADS if x["id"] != load_id]
    if len(_LOADS) == before:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Load not found",
        )
    return {"ok": True}


# --- Invoice endpoints ---

@app.get(
    "/v1/invoices",
    response_model=List[InvoiceOut],
    dependencies=[Depends(guard("admin", "dispatcher", "viewer"))],
)
def list_invoices():
    return _INVOICES


@app.post(
    "/v1/invoices",
    response_model=InvoiceOut,
    dependencies=[Depends(guard("admin"))],
)
def create_invoice(inv: InvoiceIn):
    new = inv.dict()
    new["id"] = f"i{len(_INVOICES) + 1}"
    _INVOICES.append(new)
    return new


@app.delete(
    "/v1/invoices/{invoice_id}",
    dependencies=[Depends(guard("admin"))],
)
def delete_invoice(invoice_id: str):
    global _INVOICES
    before = len(_INVOICES)
    _INVOICES = [x for x in _INVOICES if x["id"] != invoice_id]
    if len(_INVOICES) == before:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invoice not found",
        )
    return {"ok": True}

