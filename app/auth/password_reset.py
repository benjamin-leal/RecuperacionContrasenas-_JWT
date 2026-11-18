from datetime import timedelta
from uuid import UUID, uuid4

import jwt
from fastapi import HTTPException
from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from app.auth.password import hash_password
from app.shared.config import RESET_DEMO_ENABLED, RESET_JWT_SECRET
from app.shared.datetimes import utc_now
from app.users.password_reset_models import PasswordResetTokenModel
from app.users.users_models import UserModel, UserSessionModel
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


def reset_password(db: Session, token: str, password: str) -> None:
    invalid = HTTPException(401, "Enlace inválido, vencido o utilizado")
    try:
        claims = jwt.decode(
            token,
            signing_key(),
            algorithms=["HS256"],
            options={"require": ["sub", "jti", "exp", "purpose"]},
        )
        user_id = UUID(claims["sub"])
        if claims["purpose"] != "password_reset":
            raise invalid
    except (jwt.InvalidTokenError, ValueError, TypeError, OverflowError) as exc:
        raise invalid from exc

    now = utc_now()
    with db.begin():
        # Solo una solicitud puede pasar de pendiente a utilizado.
        consumed = db.scalar(
            update(PasswordResetTokenModel)
            .where(
                PasswordResetTokenModel.id == claims["jti"],
                PasswordResetTokenModel.userId == user_id,
                PasswordResetTokenModel.usedAt.is_(None),
                PasswordResetTokenModel.expiresAt > now,
            )
            .values(usedAt=now)
            .returning(PasswordResetTokenModel.id)
        )
        if consumed is None:
            raise invalid
        db.execute(
            update(UserModel)
            .where(UserModel.id == user_id)
            .values(passwordHash=hash_password(password))
        )
        db.execute(delete(UserSessionModel).where(UserSessionModel.userId == user_id))
