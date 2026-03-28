"""merge heads

Revision ID: 1130f7259f8a
Revises: 4d6b8b0f3f62, df814258c022
Create Date: 2026-04-01 19:01:15.731848

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "1130f7259f8a"
down_revision: str | Sequence[str] | None = ("4d6b8b0f3f62", "df814258c022")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
