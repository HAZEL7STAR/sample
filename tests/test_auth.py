import hashlib
import sys
import unittest
from pathlib import Path

from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.api import users
from app.models import models


class AuthHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def test_duplicate_user_creation_is_rejected(self) -> None:
        session = self.Session()
        try:
            users.create_user({"username": "alice", "password": "secret", "role": "viewer"}, db=session)
            with self.assertRaises(HTTPException):
                users.create_user({"username": "alice", "password": "another", "role": "viewer"}, db=session)
        finally:
            session.close()

    def test_legacy_sha256_passwords_still_verify(self) -> None:
        legacy_hash = hashlib.sha256(b"secret").hexdigest()
        from app.api.auth import verify_password

        self.assertTrue(verify_password("secret", legacy_hash))
        self.assertFalse(verify_password("wrong", legacy_hash))


if __name__ == "__main__":
    unittest.main()
