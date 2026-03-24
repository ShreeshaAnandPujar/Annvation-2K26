from functools import lru_cache
from fastapi import Depends
from app.config import Settings, get_settings


def get_settings_dep() -> Settings:
    return get_settings()
