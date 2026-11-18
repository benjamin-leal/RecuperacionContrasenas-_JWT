from datetime import timedelta
from uuid import uuid4

import jwt
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.shared.config import RESET_DEMO_ENABLED, RESET_JWT_SECRET
from app.shared.datetimes import utc_now
from app.users.password_reset_models import PasswordResetTokenModel
from app.users.users_repository import UsersRepository


def signing_key() -> str:
    if len(RESET_JWT_SECRET.encode()) < 32:
        raise HTTPException(503, "Configura la clave de recuperación")
    return RESET_JWT_SECRET


def request_reset(db: Session, email: str) -> dict[str, str]:
    # La actividad entrega el enlace en la respuesta solo en la demo local.
    if not RESET_DEMO_ENABLED:
        raise HTTPException(503, "Entrega de enlaces de demostración deshabilitada")
    key = signing_key()
    user = UsersRepository(db).find_by_email(email)
    result = {"message": "Solicitud de recuperación recibida"}
    if user is None:
        return result

    expires = utc_now() + timedelta(minutes=15)
    jti = str(uuid4())
    token = jwt.encode(
        {"sub": str(user.id), "jti": jti, "purpose": "password_reset", "exp": expires},
        key,
        algorithm="HS256",
    )
    db.add(PasswordResetTokenModel(id=jti, userId=user.id, expiresAt=expires))
    db.commit()
    result["reset_link"] = f"/reset-password.html#{token}"
    return result
