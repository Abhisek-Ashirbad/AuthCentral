import base64
import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from typing import Protocol


PASSWORD_ITERATIONS = 310_000


@dataclass(frozen=True)
class User:
    username: str
    password_hash: str


class UserStore(Protocol):
    def get(self, username: str) -> User | None: ...

    def create(self, username: str, password: str) -> bool: ...

    def verify(self, username: str, password: str) -> User | None: ...


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return f"{base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        encoded_salt, encoded_digest = stored_hash.split("$", 1)
        salt = base64.urlsafe_b64decode(encoded_salt)
        expected_digest = base64.urlsafe_b64decode(encoded_digest)
    except (ValueError, TypeError):
        return False
    actual_digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    return hmac.compare_digest(actual_digest, expected_digest)


class InMemoryUserStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._lock = threading.Lock()

    def get(self, username: str) -> User | None:
        with self._lock:
            return self._users.get(username.casefold())

    def create(self, username: str, password: str) -> bool:
        normalized_username = username.casefold()
        user = User(username=username, password_hash=_hash_password(password))
        with self._lock:
            if normalized_username in self._users:
                return False
            self._users[normalized_username] = user
            return True

    def verify(self, username: str, password: str) -> User | None:
        user = self.get(username)
        if user is None or not _verify_password(password, user.password_hash):
            return None
        return user
