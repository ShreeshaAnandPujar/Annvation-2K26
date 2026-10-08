from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

connect_args = {}
engine_kwargs = {
    "echo": settings.app_env == "development",
}

if "postgresql" in settings.database_url:
    connect_args["server_settings"] = {"statement_timeout": "5000"}
    engine_kwargs.update({
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 10,
        "pool_timeout": 30,
        "pool_recycle": 1800,
        "connect_args": connect_args,
    })

engine = create_async_engine(settings.database_url, **engine_kwargs)

AsyncSessionFactory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass
