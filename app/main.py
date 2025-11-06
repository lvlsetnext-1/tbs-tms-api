from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from passlib.context import CryptContext
from typing import List, Optional, Dict, Any
import jwt
import time
import io
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

# --- Security / JWT config ---

JWT_SECRET = "transportationmanagementsystem"  # move to ENV in real deployment
JWT_ALG = "HS256"
ACCESS_TOKEN_TTL_SECONDS = 60 * 60 * 8  # 8 hours

# Use pbkdf2_sha256 to avoid bcrypt quirks
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Demo users – email -> {hash, role}
_USERS = {
    "admin@tbs.local": {
        "hash": pwd_context.hash("test123"),
        "role": "admin",
    },
    "dispatcher@tbs.local": {
        "hash": pwd_context.hash("test123"),
        "role": "dispatcher",
    },
    "viewer@tbs.local": {
        "hash": pwd_context.hash("test123"),
        "role": "viewer",
    },
}

# --- FastAPI app ---

app = FastAPI(title="TB&S TMS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    # Wide open for prototype so S3 + any dev environment can hit it
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Pydantic models ---

class TokenOut(BaseModel):
    accessToken: str
    tokenType: str = "bearer"
    role: str
    email: str


class DriverIn(BaseModel):
    name: str
    licenseNo: Optional[str] = None
    phone: Optional[str] = None
    payRate: Optional[float] = None

    broker: Optional[str] = None
    mcNumber: Optional[str] = None
    demographic: Optional[str] = None
    truck: Optional[str] = None

    pickupDate: Optional[str] = None
    pickupTime: Optional[str] = None
    pickupAddress: Optional[str] = None
    deliveryDate: Optional[str] = None
    deliveryTime: Optional[str] = None
    deliveryAddress: Optional[str] = None

    deadheadMiles: Optional[float] = 0
    loadedMiles: Optional[float] = 0


class DriverOut(DriverIn):
    id: str


class LoadIn(BaseModel):
    orderNo: Optional[str] = None
    status: Optional[str] = "scheduled"
    rate: Optional[float] = 0

    driver: Optional[str] = None
    truck: Optional[str] = None
    broker: Optional[str] = None
    mcNumber: Optional[str] = None
    demographic: Optional[str] = None

    pickupDate: Optional[str] = None
    pickupTime: Optional[str] = None
    pickupAddress: Optional[str] = None
    deliveryDate: Optional[str] = None
    deliveryTime: Optional[str] = None
    deliveryAddress: Optional[str] = None

    deadheadMiles: Optional[float] = 0
    loadedMiles: Optional[float] = 0

    paidMiles: Optional[float] = 0
    pricePerGallon: Optional[float] = 0
    milesPerGallon: Optional[float] = 0

    driverPay: Optional[float] = 0
    dispatcherPay: Optional[float] = 0
    detention: Optional[float] = 0
    ow: Optional[float] = 0
    brokerRate: Optional[float] = 0

    bolRcvd: Optional[str] = None
    invoiceDate: Optional[str] = None
    estimatedPayoutDate: Optional[str] = None
    invoiceNo: Optional[str] = None


class LoadOut(LoadIn):
    id: str
    driverOrphaned: bool = False
    estimatedFuelCost: float = 0
    runTotalCost: float = 0
    companyEarnings: float = 0


# --- In-memory storage (prototype only) ---

drivers_db: List[Dict[str, Any]] = []
loads_db: List[Dict[str, Any]] = []
_order_counter = 0


def next_order_no() -> str:
    global _order_counter
    _order_counter += 1
    return f"ORD-{_order_counter:04d}"


def compute_financials(load: Dict[str, Any]) -> None:
    """Compute estimatedFuelCost, runTotalCost, companyEarnings."""
    paid_miles = float(load.get("paidMiles") or 0)
    price_pg = float(load.get("pricePerGallon") or 0)
    mpg = float(load.get("milesPerGallon") or 0)
    driver_pay = float(load.get("driverPay") or 0)
    dispatcher_pay = float(load.get("dispatcherPay") or 0)
    detention = float(load.get("detention") or 0)
    ow = float(load.get("ow") or 0)
    broker_rate = float(load.get("brokerRate") or load.get("rate") or 0)

    if paid_miles > 0 and price_pg > 0 and mpg > 0:
        est_fuel = (paid_miles / mpg) * price_pg
    else:
        est_fuel = 0.0

    run_total = est_fuel + driver_pay + dispatcher_pay + detention + ow
    earnings = broker_rate - run_total

    load["estimatedFuelCost"] = round(est_fuel, 2)
    load["runTotalCost"] = round(run_total, 2)
    load["companyEarnings"] = round(earnings, 2)


# Seed a tiny bit of demo data so UI isn't empty
def seed_demo():
    global drivers_db, loads_db, _order_counter
    if drivers_db or loads_db:
        return
    d = {
        "id": "d1",
        "name": "Sample Driver",
        "licenseNo": "GA-1234",
        "phone": "678-555-0100",
        "payRate": 0.65,
        "broker": "Spot Freight",
        "mcNumber": "123456",
        "demographic": "",
        "truck": "Truck 12",
        "pickupDate": "10/27/2025",
        "pickupTime": "09:00",
        "pickupAddress": "Savannah, GA",
        "deliveryDate": "10/28/2025",
        "deliveryTime": "15:00",
        "deliveryAddress": "Atlanta, GA",
        "deadheadMiles": 25.0,
        "loadedMiles": 220.0,
    }
    drivers_db.append(d)
    _order_counter = 1
    l = {
        "id": "l1",
        "orderNo": "ORD-0001",
        "status": "Invoice Pending",
        "driver": d["name"],
        "truck": d["truck"],
        "broker": d["broker"],
        "mcNumber": d["mcNumber"],
        "demographic": d["demographic"],
        "pickupDate": d["pickupDate"],
        "pickupTime": d["pickupTime"],
        "pickupAddress": d["pickupAddress"],
        "deliveryDate": d["deliveryDate"],
        "deliveryTime": d["deliveryTime"],
        "deliveryAddress": d["deliveryAddress"],
        "deadheadMiles": d["deadheadMiles"],
        "loadedMiles": d["loadedMiles"],
        "paidMiles": 245.0,
        "pricePerGallon": 3.75,
        "milesPerGallon": 6.0,
        "driverPay": 800.0,
        "dispatcherPay": 150.0,
        "detention": 0.0,
        "ow": 0.0,
        "brokerRate": 1450.0,
        "bolRcvd": "Yes",
        "invoiceDate": "10/29/2025",
        "estimatedPayoutDate": "11/05/2025",
        "invoiceNo": "INV-1001",
        "driverOrphaned": False,
    }
    compute_financials(l)
    loads_db.append(l)


seed_demo()

# --- Auth helpers ---

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    username = (username or "").lower()
    user = _USERS.get(username)
    if not user:
        return None
    if not pwd_context.verify(password, user["hash"]):
        return None
    return {"email": username, "role": user["role"]}


def create_access_token(email: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "sub": email,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(request: Request) -> Dict[str, Any]:
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    token = auth.split(" ", 1)[1]
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )
    return {"email": data.get("sub"), "role": data.get("role")}


def require_role(*roles: str):
    def dep(user = Depends(get_current_user)):
        if roles and user["role"] not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden",
            )
        return user
    return dep


# --- Routes: Health / Auth ---

@app.get("/v1/health")
def health():
    return {"status": "ok"}


@app.post("/v1/auth/login", response_model=TokenOut)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    token = create_access_token(user["email"], user["role"])
    return TokenOut(
        accessToken=token,
        tokenType="bearer",
        role=user["role"],
        email=user["email"],
    )


# --- Routes: Drivers ---

@app.get("/v1/drivers", response_model=List[DriverOut])
def list_drivers(user = Depends(require_role("viewer", "dispatcher", "admin"))):
    return drivers_db


@app.post("/v1/drivers", response_model=DriverOut)
def create_driver(d: DriverIn, user = Depends(require_role("dispatcher", "admin"))):
    new = d.dict()
    new_id = f"d{len(drivers_db)+1}"
    new["id"] = new_id
    drivers_db.append(new)

    # When a driver is created, create an associated Load row
    load = {
        "id": f"l{len(loads_db)+1}",
        "orderNo": next_order_no(),
        "status": "scheduled",
        "driver": new["name"],
        "truck": new.get("truck"),
        "broker": new.get("broker"),
        "mcNumber": new.get("mcNumber"),
        "demographic": new.get("demographic"),
        "pickupDate": new.get("pickupDate"),
        "pickupTime": new.get("pickupTime"),
        "pickupAddress": new.get("pickupAddress"),
        "deliveryDate": new.get("deliveryDate"),
        "deliveryTime": new.get("deliveryTime"),
        "deliveryAddress": new.get("deliveryAddress"),
        "deadheadMiles": new.get("deadheadMiles") or 0,
        "loadedMiles": new.get("loadedMiles") or 0,
        "paidMiles": 0.0,
        "pricePerGallon": 0.0,
        "milesPerGallon": 0.0,
        "driverPay": 0.0,
        "dispatcherPay": 0.0,
        "detention": 0.0,
        "ow": 0.0,
        "brokerRate": 0.0,
        "bolRcvd": None,
        "invoiceDate": None,
        "estimatedPayoutDate": None,
        "invoiceNo": None,
        "driverOrphaned": False,
    }
    compute_financials(load)
    loads_db.append(load)

    return new


@app.put("/v1/drivers/{driver_id}", response_model=DriverOut)
def update_driver(driver_id: str, d: DriverIn, user = Depends(require_role("dispatcher", "admin"))):
    target = None
    for drv in drivers_db:
        if drv["id"] == driver_id:
            target = drv
            break
    if not target:
        raise HTTPException(status_code=404, detail="Driver not found")

    old_name = target["name"]
    data = d.dict()
    target.update(data)

    # Propagate fields to loads where driver name matches
    for ld in loads_db:
        if ld.get("driver") == old_name:
            ld["driver"] = target["name"]
            ld["truck"] = target.get("truck")
            ld["broker"] = target.get("broker")
            ld["mcNumber"] = target.get("mcNumber")
            ld["demographic"] = target.get("demographic")
            ld["pickupDate"] = target.get("pickupDate")
            ld["pickupTime"] = target.get("pickupTime")
            ld["pickupAddress"] = target.get("pickupAddress")
            ld["deliveryDate"] = target.get("deliveryDate")
            ld["deliveryTime"] = target.get("deliveryTime")
            ld["deliveryAddress"] = target.get("deliveryAddress")
            ld["deadheadMiles"] = target.get("deadheadMiles") or 0
            ld["loadedMiles"] = target.get("loadedMiles") or 0
            # highlight impacted loads per BR-DRV-008
            ld["driverOrphaned"] = True
            compute_financials(ld)

    return target


@app.delete("/v1/drivers/{driver_id}")
def delete_driver(driver_id: str, user = Depends(require_role("admin"))):
    global drivers_db
    target = None
    for drv in drivers_db:
        if drv["id"] == driver_id:
            target = drv
            break
    if not target:
        raise HTTPException(status_code=404, detail="Driver not found")

    drivers_db = [d for d in drivers_db if d["id"] != driver_id]

    # Mark associated loads as orphaned so UI can highlight them
    name = target["name"]
    for ld in loads_db:
        if ld.get("driver") == name:
            ld["driverOrphaned"] = True

    return {"ok": True}


# --- Routes: Loads ---

@app.get("/v1/loads", response_model=List[LoadOut])
def list_loads(user = Depends(require_role("viewer", "dispatcher", "admin"))):
    for ld in loads_db:
        compute_financials(ld)
    return loads_db


@app.post("/v1/loads", response_model=LoadOut)
def create_load(l: LoadIn, user = Depends(require_role("dispatcher", "admin"))):
    data = l.dict()
    new_id = f"l{len(loads_db)+1}"
    data["id"] = new_id
    if not data.get("orderNo"):
        data["orderNo"] = next_order_no()
    if "driverOrphaned" not in data:
        data["driverOrphaned"] = False
    compute_financials(data)
    loads_db.append(data)
    return data


@app.put("/v1/loads/{load_id}", response_model=LoadOut)
def update_load(load_id: str, l: LoadIn, user = Depends(require_role("dispatcher", "admin"))):
    target = None
    for ld in loads_db:
        if ld["id"] == load_id:
            target = ld
            break
    if not target:
        raise HTTPException(status_code=404, detail="Load not found")

    data = l.dict()
    # Preserve existing id and driverOrphaned unless explicitly changed
    keep_id = target["id"]
    keep_orphan = target.get("driverOrphaned", False)
    target.update(data)
    target["id"] = keep_id
    if "driverOrphaned" not in data:
        target["driverOrphaned"] = keep_orphan

    compute_financials(target)
    return target


@app.delete("/v1/loads/{load_id}")
def delete_load(load_id: str, user = Depends(require_role("dispatcher", "admin"))):
    global loads_db
    before = len(loads_db)
    loads_db = [ld for ld in loads_db if ld["id"] != load_id]
    if len(loads_db) == before:
        raise HTTPException(status_code=404, detail="Load not found")
    return {"ok": True}


# --- Routes: Invoice PDF ---

@app.get("/v1/loads/{load_id}/invoice/pdf")
def download_invoice_pdf(
    load_id: str,
    user = Depends(require_role("viewer", "dispatcher", "admin")),
):
    # Find the load
    load = next((l for l in loads_db if str(l["id"]) == str(load_id)), None)
    if not load:
        raise HTTPException(status_code=404, detail="Load not found")

    # Pull invoice fields
    order_no = load.get("orderNo") or ""
    pickup_date = load.get("pickupDate") or ""
    broker = load.get("broker") or ""
    invoice_no = load.get("invoiceNo") or ""
    invoice_date = load.get("invoiceDate") or pickup_date or ""
    rate = float(load.get("brokerRate") or load.get("rate") or 0)
    detention = float(load.get("detention") or 0)
    ow = float(load.get("ow") or 0)
    storage = 0.0
    chassis = 0.0
    hazmat = 0.0
    reefer = 0.0
    pre_pull = 0.0

    total = rate + storage + chassis + detention + hazmat + reefer + ow + pre_pull

    # Create PDF in memory
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    y = height - 50

    # Header – left side
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "TB&S TRANSPORTATION LLC")
    c.setFont("Helvetica", 10)
    y -= 14
    c.drawString(50, y, "Savannah, GA 31406")
    y -= 14
    c.drawString(50, y, "678.551.5955")
    y -= 14
    c.drawString(50, y, "finance@tbandstransportation.com")
    y -= 20
    c.drawString(50, y, "SPECIAL INSTRUCTION: PLEASE APPLY QUICKPAY")

    # Header – right side meta
    y_meta = height - 50
    c.setFont("Helvetica", 10)
    c.drawRightString(width - 50, y_meta, f"Invoice #: {invoice_no}")
    y_meta -= 14
    c.drawRightString(width - 50, y_meta, f"Date: {invoice_date}")
    y_meta -= 14
    c.drawRightString(width - 50, y_meta, f"Order #: {order_no}")
    y_meta -= 14
    c.drawRightString(width - 50, y_meta, f"Client: {broker}")

    # Table header
    y -= 60
    c.setFont("Helvetica-Bold", 10)
    headers = [
        "DATE", "CONTAINER/PO #", "COMMODITY", "RATE",
        "STORAGE", "CHASSIS", "DETENTION", "HAZMAT",
        "REEFER", "OW", "PRE-PULL", "Total",
    ]
    # Simple column positions (tuned for letter width)
    x_positions = [50, 120, 220, 280, 330, 380, 435, 490, 540, 590, 640, 690]

    for x, text in zip(x_positions, headers):
        c.drawString(x, y, text)

    # Table row
    y -= 18
    c.setFont("Helvetica", 10)
    values = [
        pickup_date,
        order_no,          # Container/PO #
        "",                # Commodity intentionally blank
        f"{rate:.2f}",
        f"{storage:.2f}",
        f"{chassis:.2f}",
        f"{detention:.2f}",
        f"{hazmat:.2f}",
        f"{reefer:.2f}",
        f"{ow:.2f}",
        f"{pre_pull:.2f}",
        f"{total:.2f}",
    ]
    for x, text in zip(x_positions, values):
        c.drawString(x, y, text)

    # Footer
    y -= 40
    c.drawString(50, y, "Routing#: 256074974")
    y -= 14
    c.drawString(50, y, "Acct#: 7116467999")

    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(width - 50, y, f"Grand Total: ${total:.2f}")

    c.showPage()
    c.save()
    buf.seek(0)

    filename = f'invoice-{invoice_no or order_no or load_id}.pdf'
    return StreamingResponse(
        buf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename=\"{filename}\"'
        },
    )

