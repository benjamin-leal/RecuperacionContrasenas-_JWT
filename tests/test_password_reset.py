import secrets
import unittest
from concurrent.futures import ThreadPoolExecutor
from tempfile import TemporaryDirectory
from unittest.mock import patch

import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.main import app
from app.shared.database import Base, get_db


class PasswordResetTests(unittest.TestCase):
    def setUp(self):
        folder = self.enterContext(TemporaryDirectory())
        engine = create_engine(f"sqlite:///{folder}/test.db")
        self.addCleanup(engine.dispose)
        Base.metadata.create_all(engine)

        def test_db():
            with Session(engine, expire_on_commit=False) as db:
                yield db

        app.dependency_overrides[get_db] = test_db
        self.addCleanup(app.dependency_overrides.pop, get_db)
        self.key = secrets.token_hex(32)
        self.enterContext(
            patch.multiple(
                "app.auth.password_reset",
                RESET_DEMO_ENABLED=True,
                RESET_JWT_SECRET=self.key,
            )
        )
        self.client = self.enterContext(TestClient(app))
        self.login = {"email": "ana@example.com", "password": "anterior123"}
        result = self.client.post(
            "/api/auth/register", json={"name": "Ana", **self.login}
        )
        self.assertEqual(result.status_code, 201)
        forgot = self.client.post(
            "/api/auth/password/forgot", json={"email": self.login["email"]}
        )
        self.assertEqual(forgot.status_code, 200)
        page, self.token = forgot.json()["data"]["reset_link"].split("#")
        self.assertEqual(self.client.get(page).status_code, 200)

    def reset(self, token):
        return self.client.post(
            "/api/auth/password/reset",
            json={"reset_token": token, "new_password": "actualizada123"},
        )

    def test_cambio_y_sesiones(self):
        self.assertEqual(self.client.get("/api/auth/me").status_code, 200)
        result = self.reset(self.token)
        self.assertEqual((result.status_code, result.content), (204, b""))
        self.assertEqual(self.reset(self.token).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        self.assertEqual(
            self.client.post("/api/auth/login", json=self.login).status_code, 401
        )
        login = {**self.login, "password": "actualizada123"}
        self.assertEqual(
            self.client.post("/api/auth/login", json=login).status_code, 200
        )

    def test_token_invalido(self):
        claims = jwt.decode(self.token, self.key, algorithms=["HS256"])
        for token in (
            jwt.encode(claims, secrets.token_hex(32)),
            jwt.encode({**claims, "exp": 1}, self.key),
            jwt.encode({**claims, "purpose": "other"}, self.key),
            jwt.encode({**claims, "jti": "desconocido"}, self.key),
        ):
            self.assertEqual(self.reset(token).status_code, 401)
        self.assertEqual(
            self.client.post("/api/auth/login", json=self.login).status_code, 200
        )
        self.assertEqual(self.reset(self.token).status_code, 204)

    def test_correo_desconocido(self):
        response = self.client.post(
            "/api/auth/password/forgot", json={"email": "otra@example.com"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("reset_link", response.json()["data"])

    def test_consumo_concurrente(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(self.reset, [self.token, self.token]))
        self.assertEqual(sorted(r.status_code for r in responses), [204, 401])
