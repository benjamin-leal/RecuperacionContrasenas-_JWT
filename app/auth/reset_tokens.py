from datetime import timedelta
from uuid import uuid4

import jwt
from sqlalchemy.orm import Session

from app.shared.config import (
    JWT_ALGORITHM,
    JWT_SECRET,
    PASSWORD_RESET_EXPIRE_MINUTES,
)
from app.shared.datetimes import utc_now
from app.users.password_reset_models import PasswordResetTokenModel
from app.users.users_models import UserModel

PASSWORD_RESET_PURPOSE = "password_reset"


# PROVISORIO (Integrante 1): reemplazar por la versión real manteniendo
# el nombre y la firma.
def create_password_reset_token(db: Session, user: UserModel) -> str:
    now = utc_now()
    expires_at = now + timedelta(minutes=PASSWORD_RESET_EXPIRE_MINUTES)
    jti = uuid4().hex

    token = jwt.encode(
        {
            "sub": str(user.id),
            "jti": jti,
            "purpose": PASSWORD_RESET_PURPOSE,
            "iat": now,
            "exp": expires_at,
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    db.add(PasswordResetTokenModel(id=jti, userId=user.id, expiresAt=expires_at))
    db.commit()

    return token