import os
import time
from typing import List, Optional, Dict, Any

import jwt
from fastapi import FastAPI, Depends, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel

import io
from fastapi.responses import StreamingResponse
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter


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
app = FastAPI(title="TB&S TMS API", version="0.7")

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
      "exp": now + 60 * 60 * 8,
  }
  return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def verify_token(token: str) -> Dict[str, Any]:
  try:
      return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
  except jwt.PyJWTError:
      raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")


def guard(*roles: str):
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
  deadheadMiles: Optional[float] = 0.0
  loadedMiles: Optional[float] = 0.0


class DriverOut(DriverIn):
  id: str


class LoadIn(BaseModel):
  orderNo: Optional[str] = None
  status: str = "scheduled"
  driver: Optional[str] = None
  truck: Optional[str] = None
  rate: Optional[float] = 0.0

  broker: Optional[str] = None
  mcNumber: Optional[str] = None
  demographic: Optional[str] = None
  pickupDate: Optional[str] = None
  pickupTime: Optional[str] = None
  pickupAddress: Optional[str] = None
  deliveryDate: Optional[str] = None
  deliveryTime: Optional[str] = None
  deliveryAddress: Optional[str] = None
  deadheadMiles: Optional[float] = 0.0
  loadedMiles: Optional[float] = 0.0

  # Financials
  paidMiles: Optional[float] = 0.0
  pricePerGallon: Optional[float] = 0.0
  milesPerGallon: Optional[float] = 0.0
  driverPay: Optional[float] = 0.0
  dispatcherPay: Optional[float] = 0.0
  detention: Optional[float] = 0.0
  ow: Optional[float] = 0.0
  brokerRate: Optional[float] = 0.0
  bolRcvd: Optional[str] = None  # Yes / No / Bobtail only
  invoiceDate: Optional[str] = None
  estimatedPayoutDate: Optional[str] = None
  invoiceNo: Optional[str] = None

  estimatedFuelCost: Optional[float] = 0.0
  runTotalCost: Optional[float] = 0.0
  companyEarnings: Optional[float] = 0.0


class LoadOut(LoadIn):
  id: str
  driverOrphaned: bool = False

# -------------------------------------------------------------------
# In-memory data
# -------------------------------------------------------------------
_DRIVERS: List[Dict[str, Any]] = [
  {
      "id": "d1",
      "name": "Ava Johnson",
      "licenseNo": "GA-1234",
      "phone": "404-555-0101",
      "payRate": 0.62,
      "broker": None,
      "mcNumber": None,
      "demographic": None,
      "truck": "Truck 12",
      "pickupDate": None,
      "pickupTime": None,
      "pickupAddress": None,
      "deliveryDate": None,
      "deliveryTime": None,
      "deliveryAddress": None,
      "deadheadMiles": 0.0,
      "loadedMiles": 0.0,
  },
  {
      "id": "d2",
      "name": "Marcus Lee",
      "licenseNo": "GA-5678",
      "phone": "470-555-0147",
      "payRate": 0.65,
      "broker": None,
      "mcNumber": None,
      "demographic": None,
      "truck": "Truck 08",
      "pickupDate": None,
      "pickupTime": None,
      "pickupAddress": None,
      "deliveryDate": None,
      "deliveryTime": None,
      "deliveryAddress": None,
      "deadheadMiles": 0.0,
      "loadedMiles": 0.0,
  },
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
      "broker": None,
      "mcNumber": None,
      "demographic": None,
      "pickupDate": None,
      "pickupTime": None,
      "pickupAddress": None,
      "deliveryDate": None,
      "deliveryTime": None,
      "deliveryAddress": None,
      "deadheadMiles": 0.0,
      "loadedMiles": 0.0,
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
      "estimatedFuelCost": 0.0,
      "runTotalCost": 0.0,
      "companyEarnings": 0.0,
  },
  {
      "id": "l2",
      "orderNo": "ORD-1002",
      "status": "in_transit",
      "driver": "Marcus Lee",
      "truck": "Truck 08",
      "rate": 980.0,
      "driverOrphaned": False,
      "broker": None,
      "mcNumber": None,
      "demographic": None,
      "pickupDate": None,
      "pickupTime": None,
      "pickupAddress": None,
      "deliveryDate": None,
      "deliveryTime": None,
      "deliveryAddress": None,
      "deadheadMiles": 0.0,
      "loadedMiles": 0.0,
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
      "estimatedFuelCost": 0.0,
      "runTotalCost": 0.0,
      "companyEarnings": 0.0,
  },
]

# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def _next_order_no() -> str:
  max_n = 1000
  for l in _LOADS:
      o = l.get("orderNo")
      if isinstance(o, str) and o.startswith("ORD-"):
          try:
              n = int(o.split("-")[1])
              if n > max_n:
                  max_n = n
          except ValueError:
              continue
  return f"ORD-{max_n + 1}"


def _compute_financials(d: Dict[str, Any]) -> None:
  """
  Derive Estimated Fuel Cost, Run Total Cost, and Company Earnings.

  Estimated Fuel Cost = (Paid Miles / Miles Per Gallon) * Price Per Gallon
  Run Total Cost     = Driver Pay + Dispatcher Pay + Detention + OW + Estimated Fuel Cost
  Company Earnings   = Broker Rate - Run Total Cost
  """
  def f(name: str) -> float:
      try:
          return float(d.get(name) or 0.0)
      except (TypeError, ValueError):
          return 0.0

  paid_miles = max(0.0, f("paidMiles"))
  price_pg   = max(0.0, f("pricePerGallon"))
  mpg        = max(0.0, f("milesPerGallon"))
  driver_pay = f("driverPay")
  dispatch_pay = f("dispatcherPay")
  detention = f("detention")
  ow = f("ow")
  broker_rate = f("brokerRate")

  est_fuel = 0.0
  if paid_miles > 0 and mpg > 0 and price_pg > 0:
      est_fuel = (paid_miles / mpg) * price_pg

  run_total = driver_pay + dispatch_pay + detention + ow + est_fuel
  company_earnings = broker_rate - run_total

  d["estimatedFuelCost"] = round(est_fuel, 2)
  d["runTotalCost"] = round(run_total, 2)
  d["companyEarnings"] = round(company_earnings, 2)

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
@app.get("/v1/drivers", response_model=List[DriverOut], dependencies=[guard("admin","dispatcher","viewer")])
def list_drivers():
  return _DRIVERS


@app.post("/v1/drivers", response_model=DriverOut, dependencies=[guard("admin","dispatcher")])
def create_driver(d: DriverIn):
  global _LOADS

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

  order_no = _next_order_no()
  ld: Dict[str, Any] = {
      "id": f"l{len(_LOADS) + 1}",
      "orderNo": order_no,
      "status": "scheduled",
      "driver": d.name,
      "truck": d.truck or "",
      "rate": d.payRate or 0.0,
      "driverOrphaned": False,
      "broker": d.broker,
      "mcNumber": d.mcNumber,
      "demographic": d.demographic,
      "pickupDate": d.pickupDate,
      "pickupTime": d.pickupTime,
      "pickupAddress": d.pickupAddress,
      "deliveryDate": d.deliveryDate,
      "deliveryTime": d.deliveryTime,
      "deliveryAddress": d.deliveryAddress,
      "deadheadMiles": d.deadheadMiles or 0.0,
      "loadedMiles": d.loadedMiles or 0.0,
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
      "estimatedFuelCost": 0.0,
      "runTotalCost": 0.0,
      "companyEarnings": 0.0,
  }
  _compute_financials(ld)
  _LOADS.append(ld)
  return new


@app.put("/v1/drivers/{driver_id}", response_model=DriverOut, dependencies=[guard("admin","dispatcher")])
def update_driver(driver_id: str, d: DriverIn):
  global _LOADS

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

          for load in _LOADS:
              if load.get("driver") == old_name:
                  load["driver"] = d.name
                  load["truck"] = d.truck or load.get("truck", "")
                  load["rate"] = d.payRate or 0.0
                  load["broker"] = d.broker
                  load["mcNumber"] = d.mcNumber
                  load["demographic"] = d.demographic
                  load["pickupDate"] = d.pickupDate
                  load["pickupTime"] = d.pickupTime
                  load["pickupAddress"] = d.pickupAddress
                  load["deliveryDate"] = d.deliveryDate
                  load["deliveryTime"] = d.deliveryTime
                  load["deliveryAddress"] = d.deliveryAddress
                  load["deadheadMiles"] = d.deadheadMiles or 0.0
                  load["loadedMiles"] = d.loadedMiles or 0.0
                  load["driverOrphaned"] = True
                  _compute_financials(load)

          return drv

  raise HTTPException(status_code=404, detail="Not found")


@app.delete("/v1/drivers/{driver_id}", dependencies=[guard("admin","dispatcher")])
def delete_driver(driver_id: str):
  global _DRIVERS, _LOADS

  deleted_name: Optional[str] = None
  remaining: List[Dict[str, Any]] = []
  for drv in _DRIVERS:
      if drv["id"] == driver_id:
          deleted_name = drv["name"]
      else:
          remaining.append(drv)

  if deleted_name is None:
      raise HTTPException(status_code=404, detail="Not found")

  _DRIVERS = remaining

  for load in _LOADS:
      if load.get("driver") == deleted_name:
          load["driverOrphaned"] = True

  return {"ok": True, "deletedDriver": deleted_name}

# -------------------------------------------------------------------
# Loads
# -------------------------------------------------------------------
@app.get("/v1/loads", response_model=List[LoadOut], dependencies=[guard("admin","dispatcher","viewer")])
def list_loads():
  return _LOADS


@app.post("/v1/loads", response_model=LoadOut, dependencies=[guard("admin","dispatcher")])
def create_load(l: LoadIn):
  new = l.dict()
  if not new.get("orderNo"):
      new["orderNo"] = _next_order_no()
  new["id"] = f"l{len(_LOADS) + 1}"
  new.setdefault("driverOrphaned", False)
  _compute_financials(new)
  _LOADS.append(new)
  return new


@app.put("/v1/loads/{load_id}", response_model=LoadOut, dependencies=[guard("admin","dispatcher")])
def update_load(load_id: str, l: LoadIn):
  for load in _LOADS:
      if load["id"] == load_id:
          prev_driver = load.get("driver")
          data = l.dict()
          load.update(data)
          if not load.get("orderNo"):
              load["orderNo"] = _next_order_no()
          if load.get("driver") != prev_driver:
              load["driverOrphaned"] = False
          _compute_financials(load)
          load["id"] = load_id
          return load

  raise HTTPException(status_code=404, detail="Not found")


@app.delete("/v1/loads/{load_id}", dependencies=[guard("admin","dispatcher")])
def delete_load(load_id: str):
  global _LOADS
  before = len(_LOADS)
  _LOADS = [x for x in _LOADS if x["id"] != load_id]
  if len(_LOADS) == before:
      raise HTTPException(status_code=404, detail="Not found")
  return {"ok": True}

@app.get("/v1/loads/{load_id}/invoice/pdf")
def download_invoice_pdf(
    load_id: str,
    user = Depends(require_role("viewer")),  # any authenticated role can download
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
