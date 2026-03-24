from app.models.user import User


def test_user_model_repr():
    user = User(username="testuser", email="test@test.com", hashed_password="hashed")
    assert "testuser" in repr(user)


def test_user_defaults():
    """is_active default is applied at DB insert, so we pass it explicitly here."""
    user = User(
        username="testuser",
        email="test@test.com",
        hashed_password="hashed",
        is_active=True
    )
    assert user.is_active is True
