from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from typing import Any, Dict, List
import jwt
import time

# --- Config -----------------------------------------------------------------

JWT_SECRET = "transportationmanagementsystem"   # TODO: move to env var
JWT_ALG = "HS256"

ALLOWED_ORIGINS = [
    "http://lvl-set-tms.s3-website.us-east-2.amazonaws.com",
    "https://YOUR-CUSTOM-DOMAIN",
]

# --- App --------------------------------------------------------------------

app = FastAPI(title="TB&S TMS API", version="1.0.0")

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

# --- JWT helpers ------------------------------------------------------------

def make_token(email: str, role: str, ttl_seconds: int = 60 * 60 * 8) -> str:
    now = int(time.time())
    payload = {
        "sub": email,
        "role": role,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def decode_token(token: str) -> Dict[str, Any]:
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

# --- Auth deps --------------------------------------------------------------

def get_current_user(authorization: str = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
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
    """
    Used as: dependencies=[Depends(guard("admin","dispatcher"))]
    Returns a callable dependency, not a Depends instance.
    """
    def dependency(user=Depends(get_current_user)):
        if allowed_roles and user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return user

    return dependency

# --- Schemas (simple dicts for flexibility) ---------------------------------

Driver = Dict[str, Any]
Load = Dict[str, Any]
Invoice = Dict[str, Any]

# --- Seed data & helpers ----------------------------------------------------

_DRIVERS: List[Driver] = [
    {
        "id": "d1",
        "name": "John Doe",
        "licenseNo": "GA-12345",
        "phone": "555-1234",
        "payRate": 0.65,
        "broker": "Test Freight",
        "mcNumber": "78912",
        "demographic": "Test",
        "truck": "Truck 15",
        "pickupDate": "01/15/2025",
        "pickupTime": "15:00",
        "pickupAddress": "123 Test Drive, Snellville, GA",
        "deliveryDate": "01/16/2025",
        "deliveryTime": "09:00",
        "deliveryAddress": "456 Other St, Atlanta, GA",
        "deadheadMiles": 0.0,
        "loadedMiles": 350.0,
    },
]

_LOADS: List[Load] = [
    {
        "id": "l1",
        "orderNo": "ORD-0001",
        "status": "Scheduled",
        "driverId": "d1",
        "driver": "John Doe",
        "truck": "Truck 15",
        "broker": "Test Freight",
        "mcNumber": "78912",
        "demographic": "Test",
        "origin": "Snellville, GA",
        "destination": "Atlanta, GA",
        "pickupDate": "01/15/2025",
        "pickupTime": "15:00",
        "pickupAddress": "123 Test Drive, Snellville, GA",
        "deliveryDate": "01/16/2025",
        "deliveryTime": "09:00",
        "deliveryAddress": "456 Other St, Atlanta, GA",
        "deadheadMiles": 0.0,
        "loadedMiles": 350.0,
        "paidMiles": 350.0,
        "pricePerGallon": 0.0,
        "milesPerGallon": 0.0,
        "driverPay": 0.0,
        "dispatcherPay": 0.0,
        "detention": 0.0,
        "ow": 0.0,
        "brokerRate": 1450.0,
        "bolRcvd": False,
        "invoiceDate": None,
        "estimatedPayoutDate": None,
        "invoiceNo": None,
        "estFuel": 0.0,
        "runTotal": 1450.0,
        "companyEarnings": 1450.0,
        "driverOrphaned": False,
        "rate": 1450.0,
    }
]

_INVOICES: List[Invoice] = []   # invoices are derived from loads on the FE

def _next_driver_id() -> str:
    return f"d{len(_DRIVERS) + 1}"

def _next_load_id() -> str:
    return f"l{len(_LOADS) + 1}"

def _next_order_no() -> str:
    return f"ORD-{len(_LOADS) + 1:04d}"

def _find_driver(driver_id: str) -> Driver | None:
    for d in _DRIVERS:
        if d.get("id") == driver_id:
            return d
    return None

def _find_load(load_id: str) -> Load | None:
    for l in _LOADS:
        if l.get("id") == load_id:
            return l
    return None

def _create_load_from_driver(driver: Driver) -> Load:
    """Create a starter Load record from a driver, ensuring orderNo is not empty."""
    load: Load = {
        "id": _next_load_id(),
        "orderNo": _next_order_no(),
        "status": "Scheduled",
        "driverId": driver["id"],
        "driver": driver.get("name"),
        "truck": driver.get("truck"),
        "broker": driver.get("broker"),
        "mcNumber": driver.get("mcNumber"),
        "demographic": driver.get("demographic"),
        "pickupDate": driver.get("pickupDate"),
        "pickupTime": driver.get("pickupTime"),
        "pickupAddress": driver.get("pickupAddress"),
        "deliveryDate": driver.get("deliveryDate"),
        "deliveryTime": driver.get("deliveryTime"),
        "deliveryAddress": driver.get("deliveryAddress"),
        "deadheadMiles": driver.get("deadheadMiles", 0.0) or 0.0,
        "loadedMiles": driver.get("loadedMiles", 0.0) or 0.0,
        "paidMiles": driver.get("loadedMiles", 0.0) or 0.0,
        "rate": 0.0,
        "pricePerGallon": 0.0,
        "milesPerGallon": 0.0,
        "driverPay": 0.0,
        "dispatcherPay": 0.0,
        "detention": 0.0,
        "ow": 0.0,
        "brokerRate": 0.0,
        "bolRcvd": False,
        "invoiceDate": None,
        "estimatedPayoutDate": None,
        "invoiceNo": None,
        "estFuel": 0.0,
        "runTotal": 0.0,
        "companyEarnings": 0.0,
        "driverOrphaned": False,
    }
    _LOADS.append(load)
    return load

def _sync_driver_to_loads(driver: Driver) -> None:
    """Update loads tied to this driver to reflect key driver fields."""
    driver_id = driver.get("id")
    if not driver_id:
        return
    for load in _LOADS:
        if load.get("driverId") == driver_id:
            load["driver"] = driver.get("name")
            load["truck"] = driver.get("truck")
            load["broker"] = driver.get("broker")
            load["mcNumber"] = driver.get("mcNumber")
            load["demographic"] = driver.get("demographic")
            load["pickupDate"] = driver.get("pickupDate")
            load["pickupTime"] = driver.get("pickupTime")
            load["pickupAddress"] = driver.get("pickupAddress")
            load["deliveryDate"] = driver.get("deliveryDate")
            load["deliveryTime"] = driver.get("deliveryTime")
            load["deliveryAddress"] = driver.get("deliveryAddress")
            load["deadheadMiles"] = driver.get("deadheadMiles", 0.0) or 0.0
            load["loadedMiles"] = driver.get("loadedMiles", 0.0) or 0.0
            load["paidMiles"] = load.get("loadedMiles", 0.0) or 0.0

from fastapi import Depends  # you already have this at the top

# ...

@app.get(
    "/v1/loads/{load_id}/invoice/pdf",
    dependencies=[Depends(guard("admin", "dispatcher", "viewer"))],
)
def download_invoice_pdf(load_id: str):
    # 1) Find the load
    load = next((l for l in _LOADS if l.get("id") == load_id), None)
    if not load:
        # This is the "Details Not Found" you are seeing now
        raise HTTPException(status_code=404, detail="Details Not Found")

    # 2) Validate required invoice fields (same rules as frontend)
    missing = get_invoice_missing_fields(load)
    if missing:
        # Frontend will show this in the toast
        raise HTTPException(
            status_code=400,
            detail="Details Not Found: missing " + ", ".join(missing),
        )

    # 3) Build a simple 1-page PDF invoice
    #    (This uses reportlab; add 'reportlab' to requirements.txt.)
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.pdfgen import canvas
    except ImportError:
        # Fallback: return a plain text file if reportlab isn't installed yet
        content = "INVOICE\n\n" + "\n".join(
            [
                f"Invoice #: {load.get('invoiceNo')}",
                f"Order #: {load.get('orderNo')}",
                f"Date: {(load.get('invoiceDate') or load.get('pickupDate') or '')}",
                f"Client: {load.get('broker')}",
                f"Amount: ${calc_amount_from_load(load):.2f}",
            ]
        )
        buf = BytesIO(content.encode("utf-8"))
        filename = f"invoice-{load.get('invoiceNo') or load.get('orderNo') or load_id}.txt"
        return StreamingResponse(
            buf,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename=\"{filename}\"'},
        )

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER

    y = height - 72
    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, y, "INVOICE")

    y -= 30
    c.setFont("Helvetica", 11)
    lines = [
        f"Invoice #: {load.get('invoiceNo')}",
        f"Order #: {load.get('orderNo')}",
        f"Date: {(load.get('invoiceDate') or load.get('pickupDate') or '')}",
        f"Client: {load.get('broker')}",
        f"Truck: {load.get('truck')}",
        f"Driver: {load.get('driver')}",
    ]
    for line in lines:
        c.drawString(72, y, line)
        y -= 16

    y -= 10
    c.setFont("Helvetica-Bold", 12)
    amount = calc_amount_from_load(load)
    c.drawString(72, y, f"Grand Total: ${amount:,.2f}")

    c.showPage()
    c.save()
    buf.seek(0)

    filename = f"invoice-{load.get('invoiceNo') or load.get('orderNo') or load_id}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename=\"{filename}\"'},
    )


from io import BytesIO
from fastapi.responses import StreamingResponse
# ^^^ make sure these imports are at the top of main.py

# ...

def calc_amount_from_load(load: dict) -> float:
    """Match the frontend's calcAmount(load)."""
    base = load.get("brokerRate")
    if base is None:
        base = load.get("rate", 0)
    detention = load.get("detention", 0) or 0
    ow = load.get("ow", 0) or 0
    try:
        return float(base or 0) + float(detention) + float(ow)
    except (TypeError, ValueError):
        return 0.0


def get_invoice_missing_fields(load: dict) -> list[str]:
    """
    Same rules as invoices.html:getInvoiceMissingFields:
    - Invoice #, Order #, Date, Client (not 'Client'), Container/PO#, Grand Total > 0
    """
    missing: list[str] = []

    inv_no = str(load.get("invoiceNo") or "").strip()
    ord_no = str(load.get("orderNo") or "").strip()
    date = (load.get("invoiceDate") or load.get("pickupDate") or "").strip()
    client = str(load.get("broker") or "").strip()
    po = ord_no  # using Order # as Container/PO # for now
    amount = calc_amount_from_load(load)

    if not inv_no:
        missing.append("Invoice #")
    if not ord_no:
        missing.append("Order #")
    if not date:
        missing.append("Date")
    if not client or client.lower() == "client":
        missing.append("Client")
    if not po:
        missing.append("Container/PO #")
    if not (amount > 0):
        missing.append("Grand Total")

    return missing


# --- Auth route -------------------------------------------------------------

@app.post("/v1/auth/login")
def auth_login(form: OAuth2PasswordRequestForm = Depends()):
    email = form.username
    user = USERS.get(email)
    if not user or not pwd.verify(form.password, user["hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    token = make_token(email, user["role"])
    return {"accessToken": token, "role": user["role"]}

# --- Driver endpoints -------------------------------------------------------

@app.get("/v1/drivers", dependencies=[guard("admin", "dispatcher", "viewer")])
def list_drivers() -> List[Driver]:
    return _DRIVERS

@app.post("/v1/drivers", dependencies=[guard("admin", "dispatcher")])
def create_driver(payload: Driver) -> Driver:
    # Minimal validation: UI already ensures required fields
    if not payload.get("name"):
        raise HTTPException(status_code=400, detail="Driver name is required")
    driver: Driver = dict(payload)  # shallow copy
    driver["id"] = _next_driver_id()
    _DRIVERS.append(driver)

    # Create a corresponding load record so there is always a load with an orderNo
    _create_load_from_driver(driver)

    return driver

@app.put("/v1/drivers/{driver_id}", dependencies=[guard("admin", "dispatcher")])
def update_driver(driver_id: str, payload: Driver) -> Driver:
    driver = _find_driver(driver_id)
    if not driver:
        raise HTTPException(status_code=404, detail="Driver not found")

    driver.update(payload)
    driver["id"] = driver_id  # ensure id not overwritten

    # Keep loads in sync with updated driver info
    _sync_driver_to_loads(driver)

    return driver

@app.delete("/v1/drivers/{driver_id}", dependencies=[guard("admin")])
def delete_driver(driver_id: str):
    global _DRIVERS, _LOADS
    before = len(_DRIVERS)
    _DRIVERS = [d for d in _DRIVERS if d.get("id") != driver_id]
    if len(_DRIVERS) == before:
        raise HTTPException(status_code=404, detail="Driver not found")

    # Mark loads as orphaned if they referenced this driver
    for load in _LOADS:
        if load.get("driverId") == driver_id:
            load["driverId"] = None
            load["driverOrphaned"] = True

    return {"ok": True}

# --- Load endpoints ---------------------------------------------------------

@app.get("/v1/loads", dependencies=[guard("admin", "dispatcher", "viewer")])
def list_loads() -> List[Load]:
    return _LOADS

@app.post("/v1/loads", dependencies=[guard("admin", "dispatcher")])
def create_load(payload: Load) -> Load:
    load: Load = dict(payload)
    load["id"] = _next_load_id()
    if not load.get("orderNo"):
        load["orderNo"] = _next_order_no()
    # If driverId not set but a driver name matches, try to link
    driver_id = load.get("driverId")
    if not driver_id and load.get("driver"):
        for d in _DRIVERS:
            if d.get("name") == load["driver"]:
                driver_id = d.get("id")
                break
    load["driverId"] = driver_id
    load["driverOrphaned"] = bool(driver_id is None)
    _LOADS.append(load)
    return load

@app.put("/v1/loads/{load_id}", dependencies=[guard("admin", "dispatcher")])
def update_load(load_id: str, payload: Load) -> Load:
    load = _find_load(load_id)
    if not load:
        raise HTTPException(status_code=404, detail="Load not found")
    load.update(payload)
    load["id"] = load_id
    if not load.get("orderNo"):
        load["orderNo"] = _next_order_no()
    driver_id = load.get("driverId")
    load["driverOrphaned"] = bool(driver_id is None)
    return load

@app.delete("/v1/loads/{load_id}", dependencies=[guard("admin")])
def delete_load(load_id: str):
    global _LOADS
    before = len(_LOADS)
    _LOADS = [l for l in _LOADS if l.get("id") != load_id]
    if len(_LOADS) == before:
        raise HTTPException(status_code=404, detail="Load not found")
    return {"ok": True}

# --- Invoice endpoints (basic; UI mainly uses /loads) -----------------------

@app.get("/v1/invoices", dependencies=[guard("admin", "dispatcher", "viewer")])
def list_invoices() -> List[Invoice]:
    return _INVOICES

@app.post("/v1/invoices", dependencies=[guard("admin")])
def create_invoice(payload: Invoice) -> Invoice:
    inv: Invoice = dict(payload)
    inv["id"] = f"i{len(_INVOICES) + 1}"
    _INVOICES.append(inv)
    return inv

@app.delete("/v1/invoices/{invoice_id}", dependencies=[guard("admin")])
def delete_invoice(invoice_id: str):
    global _INVOICES
    before = len(_INVOICES)
    _INVOICES = [inv for inv in _INVOICES if inv.get("id") != invoice_id]
    if len(_INVOICES) == before:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return {"ok": True}


