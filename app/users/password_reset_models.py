from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.shared.database import Base, TimestampMixin


class PasswordResetTokenModel(TimestampMixin, Base):
    __tablename__ = "password_reset_tokens"

    # Identificador del JWT (jti).
    id: Mapped[str] = mapped_column(String(64), primary_key=True)

    # Usuario propietario del token.
    userId: Mapped[UUID] = mapped_column(
        "user_id",
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
    )

    # Fecha de expiracion del token.
    expiresAt: Mapped[datetime] = mapped_column(
        "expires_at",
        DateTime(timezone=True),
        index=True,
    )

    # Se mantiene NULL hasta que el token sea utilizado.
    usedAt: Mapped[datetime | None] = mapped_column(
        "used_at",
        DateTime(timezone=True),
        nullable=True,
    )
