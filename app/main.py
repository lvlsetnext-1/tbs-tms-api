from fastapi import FastAPI, Depends, HTTPException, status, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from fastapi.responses import StreamingResponse
from io import BytesIO
from typing import Dict, Any, List, Optional
import jwt
import time

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

JWT_SECRET = "transportationmanagementsystem"  # TODO: move to env
JWT_ALG = "HS256"

ALLOWED_ORIGINS = [
    "http://lvl-set-tms.s3-website.us-east-2.amazonaws.com",
    "https://YOUR-CUSTOM-DOMAIN",
]

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="TB&S TMS API", version="1.1.0")

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
    "admin@tbs.local":   {"hash": pwd.hash("test123"), "role": "admin"},
    "dispatch@tbs.local": {"hash": pwd.hash("test123"), "role": "dispatcher"},
    "viewer@tbs.local":  {"hash": pwd.hash("test123"), "role": "viewer"},
}

# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------

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
    Use as a dependency parameter, e.g.:

    @app.get("/v1/drivers")
    def list_drivers(user = Depends(guard("admin","dispatcher","viewer"))):
        ...
    """
    def dependency(user = Depends(get_current_user)):
        if allowed_roles and user["role"] not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return user
    return dependency

# ---------------------------------------------------------------------------
# Data stores
# ---------------------------------------------------------------------------

Driver = Dict[str, Any]
Load = Dict[str, Any]
Invoice = Dict[str, Any]

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
    }
]

_INVOICES: List[Invoice] = []

def _next_driver_id() -> str:
    return f"d{len(_DRIVERS) + 1}"

def _next_load_id() -> str:
    return f"l{len(_LOADS) + 1}"

def _next_order_no() -> str:
    return f"ORD-{len(_LOADS) + 1:04d}"

def _find_driver(driver_id: str) -> Optional[Driver]:
    for d in _DRIVERS:
        if d.get("id") == driver_id:
            return d
    return None

def _find_load(load_id: str) -> Optional[Load]:
    for l in _LOADS:
        if l.get("id") == load_id:
            return l
    return None

def _create_load_from_driver(driver: Driver) -> Load:
    """Create a basic load tied to this driver, always with an orderNo."""
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
    """Update loads tied to a driver when the driver changes."""
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

# ---------------------------------------------------------------------------
# Invoice helpers
# ---------------------------------------------------------------------------

def calc_amount_from_load(load: Load) -> float:
    base = load.get("brokerRate")
    if base is None:
        base = load.get("rate", 0)
    detention = load.get("detention", 0) or 0
    ow = load.get("ow", 0) or 0
    try:
        return float(base or 0) + float(detention) + float(ow)
    except (TypeError, ValueError):
        return 0.0


def get_invoice_missing_fields(load: Load) -> List[str]:
    missing: List[str] = []
    inv_no = str(load.get("invoiceNo") or "").strip()
    ord_no = str(load.get("orderNo") or "").strip()
    date = (load.get("invoiceDate") or load.get("pickupDate") or "").strip()
    client = str(load.get("broker") or "").strip()
    po = ord_no
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

# ---------------------------------------------------------------------------
# Auth endpoint
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Driver endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/drivers")
def list_drivers(user = Depends(guard("admin", "dispatcher", "viewer"))) -> List[Driver]:
    return _DRIVERS


@app.post("/v1/drivers")
def create_driver(driver: Driver, user = Depends(guard("admin", "dispatcher"))) -> Driver:
    if not driver.get("name"):
        raise HTTPException(status_code=400, detail="Driver name is required")

    new_driver: Driver = dict(driver)
    new_driver["id"] = _next_driver_id()
    _DRIVERS.append(new_driver)

    # automatically create a load for this driver
    _create_load_from_driver(new_driver)

    return new_driver


@app.put("/v1/drivers/{driver_id}")
def update_driver(driver_id: str, driver: Driver, user = Depends(guard("admin", "dispatcher"))) -> Driver:
    existing = _find_driver(driver_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Driver not found")

    existing.update(driver)
    existing["id"] = driver_id

    _sync_driver_to_loads(existing)

    return existing


@app.delete("/v1/drivers/{driver_id}")
def delete_driver(driver_id: str, user = Depends(guard("admin"))) -> Dict[str, Any]:
    global _DRIVERS, _LOADS
    before = len(_DRIVERS)
    _DRIVERS = [d for d in _DRIVERS if d.get("id") != driver_id]
    if len(_DRIVERS) == before:
        raise HTTPException(status_code=404, detail="Driver not found")

    # mark loads orphaned
    for load in _LOADS:
        if load.get("driverId") == driver_id:
            load["driverId"] = None
            load["driverOrphaned"] = True

    return {"ok": True}

# ---------------------------------------------------------------------------
# Load endpoints
# ---------------------------------------------------------------------------

@app.get("/v1/loads")
def list_loads(user = Depends(guard("admin", "dispatcher", "viewer"))) -> List[Load]:
    return _LOADS


@app.post("/v1/loads")
def create_load(load: Load, user = Depends(guard("admin", "dispatcher"))) -> Load:
    new_load: Load = dict(load)
    new_load["id"] = _next_load_id()
    if not new_load.get("orderNo"):
        new_load["orderNo"] = _next_order_no()

    driver_id = new_load.get("driverId")
    if not driver_id and new_load.get("driver"):
        for d in _DRIVERS:
            if d.get("name") == new_load["driver"]:
                driver_id = d.get("id")
                break
    new_load["driverId"] = driver_id
    new_load["driverOrphaned"] = bool(driver_id is None)

    _LOADS.append(new_load)
    return new_load


@app.put("/v1/loads/{load_id}")
def update_load(load_id: str, load: Load, user = Depends(guard("admin", "dispatcher"))) -> Load:
    existing = _find_load(load_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Load not found")

    existing.update(load)
    existing["id"] = load_id
    if not existing.get("orderNo"):
        existing["orderNo"] = _next_order_no()

    driver_id = existing.get("driverId")
    existing["driverOrphaned"] = bool(driver_id is None)

    return existing


@app.delete("/v1/loads/{load_id}")
def delete_load(load_id: str, user = Depends(guard("admin"))) -> Dict[str, Any]:
    global _LOADS
    before = len(_LOADS)
    _LOADS = [l for l in _LOADS if l.get("id") != load_id]
    if len(_LOADS) == before:
        raise HTTPException(status_code=404, detail="Load not found")
    return {"ok": True}

# ---------------------------------------------------------------------------
# Invoice endpoints (simple, data-only)
# ---------------------------------------------------------------------------

@app.get("/v1/invoices")
def list_invoices(user = Depends(guard("admin", "dispatcher", "viewer"))) -> List[Invoice]:
    return _INVOICES


@app.post("/v1/invoices")
def create_invoice(inv: Invoice, user = Depends(guard("admin"))) -> Invoice:
    new_inv: Invoice = dict(inv)
    new_inv["id"] = f"i{len(_INVOICES) + 1}"
    _INVOICES.append(new_inv)
    return new_inv


@app.delete("/v1/invoices/{invoice_id}")
def delete_invoice(invoice_id: str, user = Depends(guard("admin"))) -> Dict[str, Any]:
    global _INVOICES
    before = len(_INVOICES)
    _INVOICES = [i for i in _INVOICES if i.get("id") != invoice_id]
    if len(_INVOICES) == before:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return {"ok": True}

# ---------------------------------------------------------------------------
# Invoice PDF download endpoint
# ---------------------------------------------------------------------------

@app.get("/v1/loads/{load_id}/invoice/pdf")
def download_invoice_pdf(load_id: str, user = Depends(guard("admin", "dispatcher", "viewer"))):
    load = _find_load(load_id)
    if not load:
        raise HTTPException(status_code=404, detail="Details Not Found")

    missing = get_invoice_missing_fields(load)
    if missing:
        # Frontend will show this in the toast
        raise HTTPException(
            status_code=400,
            detail="Details Not Found: missing " + ", ".join(missing),
        )

    # Try to use reportlab for a nicely formatted invoice PDF
    try:
        from reportlab.lib.pagesizes import LETTER
        from reportlab.lib import colors
        from reportlab.pdfgen import canvas
    except ImportError:
        # Fallback: plain text attachment if reportlab is not available
        content_lines = [
            "INVOICE",
            "",
            f"Invoice #: {load.get('invoiceNo')}",
            f"Order #: {load.get('orderNo')}",
            f"Date: {(load.get('invoiceDate') or load.get('pickupDate') or '')}",
            f"Client: {load.get('broker')}",
            "",
            f"Grand Total: ${calc_amount_from_load(load):.2f}",
        ]
        buf = BytesIO(("\n".join(content_lines)).encode("utf-8"))
        filename = f"invoice-{load.get('invoiceNo') or load.get('orderNo') or load_id}.txt"
        return StreamingResponse(
            buf,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename=\"{filename}\"'},
        )

    # ---------- Nicely formatted PDF using reportlab ----------
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER
    margin = 50

    inv_no = load.get("invoiceNo") or ""
    ord_no = load.get("orderNo") or ""
    date = (load.get("invoiceDate") or load.get("pickupDate") or "") or ""
    client = load.get("broker") or ""
    origin = load.get("origin") or load.get("pickupAddress") or ""
    dest = load.get("destination") or load.get("deliveryAddress") or ""
    truck = load.get("truck") or ""
    driver = load.get("driver") or ""
    amount = calc_amount_from_load(load)

    detention = float(load.get("detention") or 0)
    ow = float(load.get("ow") or 0)
    base = load.get("brokerRate")
    if base is None:
        base = load.get("rate", 0)
    base = float(base or 0)

    # Header: company + "INVOICE"
    y = height - margin
    c.setFont("Helvetica-Bold", 20)
    c.setFillColor(colors.black)
    c.drawString(margin, y, "TB&S TRANSPORTATION LLC")

    c.setFont("Helvetica", 10)
    c.setFillColor(colors.grey)
    c.drawString(margin, y - 14, "Freight & Logistics Services")
    c.setFillColor(colors.black)

    c.setFont("Helvetica-Bold", 18)
    c.drawRightString(width - margin, y, "INVOICE")

    # Thin divider line
    y -= 32
    c.setLineWidth(0.5)
    c.setStrokeColor(colors.lightgrey)
    c.line(margin, y, width - margin, y)
    c.setStrokeColor(colors.black)
    y -= 24

    # Invoice details (right)
    c.setFont("Helvetica", 10)
    right_x = width - margin
    c.drawRightString(right_x, y, f"Invoice #: {inv_no}")
    y -= 14
    c.drawRightString(right_x, y, f"Order #: {ord_no}")
    y -= 14
    c.drawRightString(right_x, y, f"Date: {date}")

    # Bill To (left)
    y_bill = height - margin - 32
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y_bill, "Bill To")
    c.setFont("Helvetica", 10)
    c.drawString(margin, y_bill - 16, client or "Client")

    # Shipment summary
    y = y - 24
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, y, "Shipment Details")
    y -= 16
    c.setFont("Helvetica", 10)
    c.drawString(margin, y, f"From: {origin}")
    y -= 14
    c.drawString(margin, y, f"To:   {dest}")
    y -= 14
    if truck or driver:
        c.drawString(margin, y, f"Truck: {truck}    Driver: {driver}")
        y -= 18
    else:
        y -= 6

    # Line items table header
    table_y = y
    col_desc = margin
    col_details = margin + 250
    col_rate = width - margin - 100
    col_amount = width - margin

    c.setFont("Helvetica-Bold", 10)
    c.drawString(col_desc, table_y, "Description")
    c.drawString(col_details, table_y, "Details")
    c.drawRightString(col_rate, table_y, "Rate")
    c.drawRightString(col_amount, table_y, "Amount")

    table_y -= 16
    c.setLineWidth(0.3)
    c.setStrokeColor(colors.grey)
    c.line(margin, table_y, width - margin, table_y)
    c.setStrokeColor(colors.black)
    table_y -= 12

    # Single freight line item
    c.setFont("Helvetica", 10)
    desc = "Freight Services"
    details_parts = []
    miles = load.get("loadedMiles") or 0
    try:
        miles = float(miles)
    except (TypeError, ValueError):
        miles = 0
    if miles:
        details_parts.append(f"{miles:.0f} mi")
    if base:
        details_parts.append(f"Base ${base:,.2f}")
    if detention:
        details_parts.append(f"Detention ${detention:,.2f}")
    if ow:
        details_parts.append(f"Other ${ow:,.2f}")
    details_str = " • ".join(details_parts) or "Line haul + accessorials"

    c.drawString(col_desc, table_y, desc)
    c.drawString(col_details, table_y, details_str[:60])
    c.drawRightString(col_rate, table_y, f"${base:,.2f}")
    c.drawRightString(col_amount, table_y, f"${amount:,.2f}")
    table_y -= 26

    # Totals block on the right
    totals_y = table_y - 6
    c.setFont("Helvetica", 10)
    c.drawRightString(col_amount, totals_y, f"Base: ${base:,.2f}")
    totals_y -= 14
    c.drawRightString(col_amount, totals_y, f"Detention: ${detention:,.2f}")
    totals_y -= 14
    c.drawRightString(col_amount, totals_y, f"Other: ${ow:,.2f}")
    totals_y -= 16
    c.setLineWidth(0.5)
    c.line(col_amount - 120, totals_y, col_amount, totals_y)
    totals_y -= 18
    c.setFont("Helvetica-Bold", 11)
    c.drawRightString(col_amount, totals_y, f"Total Due: ${amount:,.2f}")

    # Footer
    c.setFont("Helvetica", 8)
    c.setFillColor(colors.grey)
    c.drawString(
        margin,
        40,
        "Please remit payment according to the agreed terms.",
    )
    c.drawRightString(
        width - margin,
        40,
        "Thank you for your business.",
    )
    c.setFillColor(colors.black)

    c.showPage()
    c.save()
    buf.seek(0)

    filename = f"invoice-{inv_no or ord_no or load_id}.pdf"
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename=\"{filename}\"'},
    )




