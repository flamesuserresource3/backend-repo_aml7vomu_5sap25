import base64
import os
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from database import get_db
from schemas import (
    UserCreate,
    UserLogin,
    UserOut,
    DepositOut,
    CoinFlipBet,
    ColorBet,
    AviatorBet,
    MinesBet,
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Utilities
import hashlib


def hash_password(password: str, salt: Optional[str] = None) -> Dict[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256()
    h.update((salt + password).encode("utf-8"))
    return {"salt": salt, "hash": h.hexdigest()}


async def get_user_by_email(db: Any, email: str) -> Optional[Dict[str, Any]]:
    return await db["user"].find_one({"email": email})


async def get_user_by_id(db: Any, user_id: str) -> Optional[Dict[str, Any]]:
    from bson import ObjectId

    try:
        oid = ObjectId(user_id)
    except Exception:
        return None
    return await db["user"].find_one({"_id": oid})


async def create_session(db: Any, user_id: str, ttl_minutes: int = 7 * 24 * 60) -> str:
    token = secrets.token_urlsafe(32)
    await db["session"].insert_one(
        {
            "user_id": user_id,
            "token": token,
            "expires_at": datetime.utcnow() + timedelta(minutes=ttl_minutes),
            "created_at": datetime.utcnow(),
        }
    )
    return token


async def get_session_user(db: Any, authorization: Optional[str]) -> Optional[Dict[str, Any]]:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(" ", 1)[1]
    session = await db["session"].find_one({"token": token})
    if not session:
        return None
    if session.get("expires_at") and session["expires_at"] < datetime.utcnow():
        return None
    user = await get_user_by_id(db, session["user_id"])
    return user


class AuthResponse(BaseModel):
    token: str
    user: UserOut


class DepositJSON(BaseModel):
    amount: float = Field(gt=0)
    receipt_data_url: str


# Routes
@app.get("/test")
async def test():
    # lightweight health check that doesn't require DB
    return {"status": "ok"}


@app.post("/auth/register", response_model=AuthResponse)
async def register(payload: UserCreate, db: Any = Depends(get_db)):
    existing = await get_user_by_email(db, payload.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    ph = hash_password(payload.password)

    # First user becomes admin
    user_count = await db["user"].count_documents({})
    is_admin = user_count == 0

    res = await db["user"].insert_one(
        {
            "email": payload.email,
            "password_hash": ph["hash"],
            "password_salt": ph["salt"],
            "is_admin": is_admin,
            "balance": 0.0,
            "created_at": datetime.utcnow(),
        }
    )
    user_id = str(res.inserted_id)
    token = await create_session(db, user_id)
    user_out = UserOut(id=user_id, email=payload.email, is_admin=is_admin, balance=0.0)
    return {"token": token, "user": user_out}


@app.post("/auth/login", response_model=AuthResponse)
async def login(payload: UserLogin, db: Any = Depends(get_db)):
    user = await get_user_by_email(db, payload.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    ph = hash_password(payload.password, user.get("password_salt"))
    if ph["hash"] != user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = await create_session(db, str(user["_id"]))
    user_out = UserOut(
        id=str(user["_id"]), email=user["email"], is_admin=user.get("is_admin", False), balance=float(user.get("balance", 0.0))
    )
    return {"token": token, "user": user_out}


@app.get("/auth/me", response_model=UserOut)
async def me(authorization: Optional[str] = Header(default=None), db: Any = Depends(get_db)):
    user = await get_session_user(db, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return UserOut(
        id=str(user["_id"]), email=user["email"] , is_admin=user.get("is_admin", False), balance=float(user.get("balance", 0.0))
    )


@app.get("/wallet")
async def get_wallet(authorization: Optional[str] = Header(default=None), db: Any = Depends(get_db)):
    user = await get_session_user(db, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"balance": float(user.get("balance", 0.0))}


@app.post("/deposits", response_model=DepositOut)
async def create_deposit(
    payload: DepositJSON,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    user = await get_session_user(db, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")

    doc = {
        "user_id": str(user["_id"]),
        "amount": float(payload.amount),
        "status": "pending",
        "receipt_data_url": payload.receipt_data_url,
        "created_at": datetime.utcnow(),
    }
    res = await db["deposit"].insert_one(doc)
    return DepositOut(
        id=str(res.inserted_id),
        user_id=doc["user_id"],
        amount=doc["amount"],
        status=doc["status"],
        created_at=doc["created_at"],
        receipt_data_url=doc["receipt_data_url"],
    )


@app.get("/deposits")
async def list_deposits(
    status: Optional[str] = None,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    user = await get_session_user(db, authorization)
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    query: Dict[str, Any] = {}
    if status:
        query["status"] = status
    cursor = db["deposit"].find(query).sort("created_at", -1)
    items = []
    async for d in cursor:
        items.append(
            {
                "id": str(d["_id"]),
                "user_id": d["user_id"],
                "amount": float(d["amount"]),
                "status": d["status"],
                "created_at": d["created_at"].isoformat() + "Z",
                "receipt_data_url": d.get("receipt_data_url"),
            }
        )
    return {"items": items}


@app.post("/deposits/{deposit_id}/approve")
async def approve_deposit(
    deposit_id: str,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    user = await get_session_user(db, authorization)
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    from bson import ObjectId

    try:
        oid = ObjectId(deposit_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")

    dep = await db["deposit"].find_one({"_id": oid})
    if not dep:
        raise HTTPException(status_code=404, detail="Not found")
    if dep.get("status") != "pending":
        raise HTTPException(status_code=400, detail="Already processed")

    # credit balance
    await db["user"].update_one({"_id": ObjectId(dep["user_id"])}, {"$inc": {"balance": float(dep["amount"])}})
    await db["deposit"].update_one({"_id": oid}, {"$set": {"status": "approved"}})
    return {"ok": True}


@app.post("/deposits/{deposit_id}/reject")
async def reject_deposit(
    deposit_id: str,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    user = await get_session_user(db, authorization)
    if not user or not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin only")
    from bson import ObjectId

    try:
        oid = ObjectId(deposit_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")

    dep = await db["deposit"].find_one({"_id": oid})
    if not dep:
        raise HTTPException(status_code=404, detail="Not found")
    if dep.get("status") != "pending":
        raise HTTPException(status_code=400, detail="Already processed")

    await db["deposit"].update_one({"_id": oid}, {"$set": {"status": "rejected"}})
    return {"ok": True}


async def debit(db: Any, user_id: str, amount: float):
    from bson import ObjectId

    if amount <= 0:
        raise HTTPException(status_code=400, detail="Invalid amount")
    res = await db["user"].find_one_and_update(
        {"_id": ObjectId(user_id), "balance": {"$gte": amount}},
        {"$inc": {"balance": -amount}},
        return_document=True,
    )
    if not res:
        raise HTTPException(status_code=400, detail="Insufficient balance")


async def credit(db: Any, user_id: str, amount: float):
    from bson import ObjectId

    await db["user"].update_one({"_id": ObjectId(user_id)}, {"$inc": {"balance": amount}})


@app.post("/games/coinflip")
async def coinflip(
    bet: CoinFlipBet,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    import random

    user = await get_session_user(db, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    await debit(db, str(user["_id"]), bet.amount)
    outcome = random.choice(["heads", "tails"])
    win = outcome == bet.choice
    payout = round(bet.amount * 1.98, 2) if win else 0.0
    if win:
        await credit(db, str(user["_id"]), payout)
    await db["gamebet"].insert_one(
        {
            "user_id": str(user["_id"]),
            "game": "coinflip",
            "amount": float(bet.amount),
            "choice": bet.choice,
            "outcome": outcome,
            "win": win,
            "payout": payout,
            "created_at": datetime.utcnow(),
        }
    )
    return {"outcome": outcome, "win": win, "payout": payout}


@app.post("/games/color")
async def color_prediction(
    bet: ColorBet,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    import random

    user = await get_session_user(db, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    await debit(db, str(user["_id"]), bet.amount)
    outcome = random.choice(["red", "green", "blue"])
    win = outcome == bet.color
    payout = round(bet.amount * 3.0, 2) if win else 0.0
    if win:
        await credit(db, str(user["_id"]), payout)
    await db["gamebet"].insert_one(
        {
            "user_id": str(user["_id"]),
            "game": "color",
            "amount": float(bet.amount),
            "choice": bet.color,
            "outcome": outcome,
            "win": win,
            "payout": payout,
            "created_at": datetime.utcnow(),
        }
    )
    return {"outcome": outcome, "win": win, "payout": payout}


@app.post("/games/aviator")
async def aviator(
    bet: AviatorBet,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    import random

    user = await get_session_user(db, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    await debit(db, str(user["_id"]), bet.amount)
    crash = round(random.uniform(1.0, 10.0), 2)
    win = bet.cashout_multiplier <= crash
    payout = round(bet.amount * bet.cashout_multiplier, 2) if win else 0.0
    if win:
        await credit(db, str(user["_id"]), payout)
    await db["gamebet"].insert_one(
        {
            "user_id": str(user["_id"]),
            "game": "aviator",
            "amount": float(bet.amount),
            "cashout_multiplier": bet.cashout_multiplier,
            "crash": crash,
            "win": win,
            "payout": payout,
            "created_at": datetime.utcnow(),
        }
    )
    return {"crash": crash, "win": win, "payout": payout}


@app.post("/games/mines")
async def mines(
    bet: MinesBet,
    authorization: Optional[str] = Header(default=None),
    db: Any = Depends(get_db),
):
    import random

    user = await get_session_user(db, authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    await debit(db, str(user["_id"]), bet.amount)
    multiplier = round(random.uniform(1.05, 4.0), 2)
    win = random.random() > 0.5
    payout = round(bet.amount * multiplier, 2) if win else 0.0
    if win:
        await credit(db, str(user["_id"]), payout)
    await db["gamebet"].insert_one(
        {
            "user_id": str(user["_id"]),
            "game": "mines",
            "amount": float(bet.amount),
            "mines": bet.mines,
            "multiplier": multiplier,
            "win": win,
            "payout": payout,
            "created_at": datetime.utcnow(),
        }
    )
    return {"multiplier": multiplier, "win": win, "payout": payout}
