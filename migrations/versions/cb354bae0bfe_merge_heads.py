"""merge heads

Revision ID: cb354bae0bfe
Revises: 1130f7259f8a
Create Date: 2026-04-01 19:09:56.471523

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "cb354bae0bfe"
down_revision: str | Sequence[str] | None = "1130f7259f8a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
