from datetime import datetime
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Literal


class UserCreate(BaseModel):
    email: EmailStr
    password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: str
    email: EmailStr
    is_admin: bool = False
    balance: float = 0.0


class DepositCreate(BaseModel):
    amount: float = Field(gt=0)


class DepositOut(BaseModel):
    id: str
    user_id: str
    amount: float
    status: Literal["pending", "approved", "rejected"]
    created_at: datetime
    receipt_data_url: Optional[str] = None


class CoinFlipBet(BaseModel):
    amount: float = Field(gt=0)
    choice: Literal["heads", "tails"]


class ColorBet(BaseModel):
    amount: float = Field(gt=0)
    color: Literal["red", "green", "blue"]


class AviatorBet(BaseModel):
    amount: float = Field(gt=0)
    cashout_multiplier: float = Field(gt=1.0)


class MinesBet(BaseModel):
    amount: float = Field(gt=0)
    mines: int = Field(ge=1, le=24)
