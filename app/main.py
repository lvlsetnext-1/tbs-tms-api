import os
import time
from typing import List, Optional, Dict, Any

import jwt
from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

# -------------------------------------------------------------------
# Config
# -------------------------------------------------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "transportationmanagementsystem")
JWT_ALG = "HS256"

ALLOWED_ORIGINS = [
    "http://lvl-set-tms.s3-website.us-east-2.amazonaws.com",
    "https://lvl-set-tms.s3.us-east-2.amazonaws.com",
    "http://localhost:5173",
    "http://localhost:3000",
]

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Demo in-memory users (all password = test123)
USERS: Dict[str, Dict[str, Any]] = {
    "admin@tbs.local": {
        "hash": pwd_context.hash("test123"),
        "role": "admin",
    },
    "dispatch@tbs.local": {
        "hash": pwd_context.hash("test123"),
        "role": "dispatcher",
    },
    "viewer@tbs.local": {
        "hash": pwd_context.hash("test123"),
        "role": "viewer",
    },
}

# -------------------------------------------------------------------
# App + CORS
# -------------------------------------------------------------------
app = FastAPI(title="TB&S TMS API", version="0.4")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
    max_age=86400,
)

# -------------------------------------------------------------------
# JWT helpers & guard
# -------------------------------------------------------------------
def create_access_token(email: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": email,
        "role": role,
        "iat": now,
        "exp": now + 60 * 60 * 8,  # 8 hours
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def verify_token(token: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def guard(*roles: str):
    """
    Usage: dependencies=[guard("admin","dispatcher")]
    If roles is empty, only checks that token is valid.
    """
    async def _dep(authorization: Optional[str] = Header(default=None)) -> Dict[str, Any]:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")

        token = authorization.split(" ", 1)[1].strip()
        claims = verify_token(token)

        if roles:
            user_role = claims.get("role")
            if user_role not in roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

        return claims

    return Depends(_dep)

# -------------------------------------------------------------------
# Pydantic models
# -------------------------------------------------------------------
class DriverIn(BaseModel):
    name: str
    licenseNo: Optional[str] = None
    phone: Optional[str] = None
    payRate: Optional[float] = 0.0


class DriverOut(DriverIn):
    id: str


class LoadIn(BaseModel):
    orderNo: str
    status: str = "scheduled"     # scheduled | in_transit | delivered | etc
    driver: Optional[str] = None  # stores the driver name
    truck: Optional[str] = None
    rate: Optional[float] = 0.0


class LoadOut(LoadIn):
    id: str
    # BR-DRV-008 / BR-DRV-009: highlight loads whose driver was edited/deleted
    driverOrphaned: bool = False

# -------------------------------------------------------------------
# In-memory data (for prototype)
# -------------------------------------------------------------------
_DRIVERS: List[Dict[str, Any]] = [
    {"id": "d1", "name": "Ava Johnson", "licenseNo": "GA-1234", "phone": "404-555-0101", "payRate": 0.62},
    {"id": "d2", "name": "Marcus Lee", "licenseNo": "GA-5678", "phone": "470-555-0147", "payRate": 0.65},
]

_LOADS: List[Dict[str, Any]] = [
    {
        "id": "l1",
        "orderNo": "ORD-1001",
        "status": "scheduled",
        "driver": "Ava Johnson",
        "truck": "Truck 12",
        "rate": 1250.0,
        "driverOrphaned": False,
    },
    {
        "id": "l2",
        "orderNo": "ORD-1002",
        "status": "in_transit",
        "driver": "Marcus Lee",
        "truck": "Truck 08",
        "rate": 980.0,
        "driverOrphaned": False,
    },
]

# -------------------------------------------------------------------
# Health
# -------------------------------------------------------------------
@app.get("/v1/health")
def health():
    return {"ok": True, "service": "tbs-api"}

# -------------------------------------------------------------------
# Auth
# -------------------------------------------------------------------
@app.post("/v1/auth/login")
async def login(form: OAuth2PasswordRequestForm = Depends()):
    email = form.username
    user = USERS.get(email)
    if not user or not pwd_context.verify(form.password, user["hash"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = create_access_token(email, user["role"])
    return {"accessToken": token, "role": user["role"]}

# -------------------------------------------------------------------
# Drivers
# -------------------------------------------------------------------
@app.get(
    "/v1/drivers",
    response_model=List[DriverOut],
    dependencies=[guard("admin", "dispatcher", "viewer")],
)
def list_drivers():
    return _DRIVERS


@app.post(
    "/v1/drivers",
    response_model=DriverOut,
    dependencies=[guard("admin", "dispatcher")],
)
def create_driver(d: DriverIn):
    # BR-DRV-002 / BR-DRV-006 validations (lightweight for prototype)
    if not d.name or len(d.name.strip()) < 2:
        raise HTTPException(status_code=400, detail="Driver name must be at least 2 characters")
    if not d.licenseNo:
        raise HTTPException(status_code=400, detail="License # is required")
    if not d.phone:
        raise HTTPException(status_code=400, detail="Phone is required")
    if d.payRate is None or d.payRate <= 0:
        raise HTTPException(status_code=400, detail="Pay rate must be > 0")

    new = d.dict()
    new["id"] = f"d{len(_DRIVERS) + 1}"
    _DRIVERS.append(new)
    return new


@app.put(
    "/v1/drivers/{driver_id}",
    response_model=DriverOut,
    dependencies=[guard("admin", "dispatcher")],
)
def update_driver(driver_id: str, d: DriverIn):
    """
    BR-DRV-004 / BR-DRV-007 / BR-DRV-008

    - Update driver record.
    - Propagate driver name changes to Loads (so Loads always show current driver name).
    - Highlight all loads that reference this driver (driverOrphaned = True)
      so users can review impacted loads.
    """
    global _LOADS

    # Basic validation (same rules as create)
    if not d.name or len(d.name.strip()) < 2:
        raise HTTPException(status_code=400, detail="Driver name must be at least 2 characters")
    if not d.licenseNo:
        raise HTTPException(status_code=400, detail="License # is required")
    if not d.phone:
        raise HTTPException(status_code=400, detail="Phone is required")
    if d.payRate is None or d.payRate <= 0:
        raise HTTPException(status_code=400, detail="Pay rate must be > 0")

    for drv in _DRIVERS:
        if drv["id"] == driver_id:
            old_name = drv["name"]
            data = d.dict()
            drv.update(data)
            drv["id"] = driver_id

            # BR-DRV-007: propagate changes to loads
            for load in _LOADS:
                if load.get("driver") == old_name:
                    # update the displayed driver name if the name changed
                    load["driver"] = d.name
                    # BR-DRV-008: highlight impacted loads
                    load["driverOrphaned"] = True

            return drv

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


@app.delete(
    "/v1/drivers/{driver_id}",
    # Admin + dispatcher allowed to delete (BR-DRV-005 / BR-DRV-009)
    dependencies=[guard("admin", "dispatcher")],
)
def delete_driver(driver_id: str):
    """
    BR-DRV-005 / BR-DRV-009 / BR-DRV-001:

    - Delete driver record.
    - Retain driver name on associated loads (orphaned reference).
    - Flag all loads that reference this driver (driverOrphaned = True)
      so they render highlighted on Loads page.
    """
    global _DRIVERS, _LOADS

    deleted_name: Optional[str] = None
    remaining: List[Dict[str, Any]] = []
    for drv in _DRIVERS:
        if drv["id"] == driver_id:
            deleted_name = drv["name"]
        else:
            remaining.append(drv)

    if deleted_name is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    _DRIVERS = remaining

    # Mark loads with this driver as orphaned
    for load in _LOADS:
        if load.get("driver") == deleted_name:
            load["driverOrphaned"] = True

    return {"ok": True, "deletedDriver": deleted_name}

# -------------------------------------------------------------------
# Loads
# -------------------------------------------------------------------
@app.get(
    "/v1/loads",
    response_model=List[LoadOut],
    dependencies=[guard("admin", "dispatcher", "viewer")],
)
def list_loads():
    return _LOADS


@app.post(
    "/v1/loads",
    response_model=LoadOut,
    dependencies=[guard("admin", "dispatcher")],
)
def create_load(l: LoadIn):
    new = l.dict()
    new["id"] = f"l{len(_LOADS) + 1}"
    # New loads are not orphaned on create
    new.setdefault("driverOrphaned", False)
    _LOADS.append(new)
    return new


@app.put(
    "/v1/loads/{load_id}",
    response_model=LoadOut,
    dependencies=[guard("admin", "dispatcher")],
)
def update_load(load_id: str, l: LoadIn):
    """
    - Update load.
    - If driver value changes (reassignment), clear driverOrphaned flag
      so highlight disappears once the load is resolved (BR-DRV-008).
    """
    for load in _LOADS:
        if load["id"] == load_id:
            prev_driver = load.get("driver")
            data = l.dict()
            load.update(data)

            # Resolve highlight when driver is changed or cleared
            if load.get("driver") != prev_driver:
                load["driverOrphaned"] = False

            load["id"] = load_id
            return load

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


@app.delete(
    "/v1/loads/{load_id}",
    dependencies=[guard("admin", "dispatcher")],
)
def delete_load(load_id: str):
    global _LOADS
    before = len(_LOADS)
    _LOADS = [x for x in _LOADS if x["id"] != load_id]
    if len(_LOADS) == before:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    return {"ok": True}
