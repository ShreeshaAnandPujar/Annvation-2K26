# tests/unit/test_config.py
from app.config import get_settings

def test_settings_load():
    settings = get_settings()
    assert settings.app_env == "test"
    assert settings.rate_limit_requests == 100
    assert settings.bloom_filter_error_rate == 0.001
    assert settings.shadow_mode_enabled is True

def test_settings_singleton():
    """lru_cache means the same object is returned every time."""
    s1 = get_settings()
    s2 = get_settings()
    assert s1 is s2
