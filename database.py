import os
from typing import Optional, Any

_client = None
_db = None


def get_database_url() -> str:
    return os.getenv("DATABASE_URL", "mongodb://localhost:27017")


def get_database_name() -> str:
    return os.getenv("DATABASE_NAME", "appdb")


def get_db() -> Any:
    global _client, _db
    if _db is None:
        try:
            from motor.motor_asyncio import AsyncIOMotorClient  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "MongoDB driver 'motor' is not installed. Please ensure requirements are installed."
            ) from e
        _client = AsyncIOMotorClient(get_database_url())
        _db = _client[get_database_name()]
    return _db
