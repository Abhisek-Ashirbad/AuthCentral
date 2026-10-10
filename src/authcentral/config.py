import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


@dataclass(frozen=True)
class AuthConfig:
    secret_key: str = field(default_factory=lambda: os.getenv("AUTHCENTRAL_SECRET_KEY") or secrets.token_urlsafe(48))
    auth_prefix: str = "/auth"
    cookie_name: str = "authcentral_session"
    cookie_domain: str | None = None
    cookie_secure: bool = False
    session_ttl_seconds: int = 3600
    issuer: str = "authcentral"
    audience: str = "authcentral-app"

    def __post_init__(self) -> None:
        if len(self.secret_key) < 32:
            raise ValueError("secret_key must be at least 32 characters long")
        if not self.auth_prefix.startswith("/") or self.auth_prefix == "/" or self.auth_prefix.endswith("/"):
            raise ValueError("auth_prefix must start with '/' and must not end with '/'")
        if self.auth_prefix.startswith("//") or any(character in self.auth_prefix for character in ("?", "#")):
            raise ValueError("auth_prefix cannot contain a query or fragment")
        if not self.cookie_name:
            raise ValueError("cookie_name cannot be empty")
        if self.session_ttl_seconds <= 0:
            raise ValueError("session_ttl_seconds must be positive")
        if not self.issuer or not self.audience:
            raise ValueError("issuer and audience cannot be empty")

    @classmethod
    def from_toml(cls, path: str | Path = "authcentral.toml") -> "AuthConfig":
        with Path(path).open("rb") as config_file:
            values: dict[str, Any] = tomllib.load(config_file)
        section = values.get("authcentral", values)
        if not isinstance(section, dict):
            raise ValueError("TOML config must contain an [authcentral] table")
        if "secret_key" not in section:
            section["secret_key"] = os.getenv("AUTHCENTRAL_SECRET_KEY") or secrets.token_urlsafe(48)
        return cls(**section)

    def to_toml(self) -> str:
        lines = ["[authcentral]"]
        for key, value in self.__dict__.items():
            if value is None:
                continue
            rendered = json.dumps(value)
            lines.append(f"{key} = {rendered}")
        return "\n".join(lines) + "\n"

    @classmethod
    def from_env(cls) -> "AuthConfig":
        secure_value = os.getenv("AUTHCENTRAL_COOKIE_SECURE", "false").lower()
        if secure_value not in {"true", "false", "1", "0", "yes", "no"}:
            raise ValueError("AUTHCENTRAL_COOKIE_SECURE must be true or false")
        return cls(
            secret_key=os.getenv("AUTHCENTRAL_SECRET_KEY") or secrets.token_urlsafe(48),
            auth_prefix=os.getenv("AUTHCENTRAL_PREFIX", "/auth"),
            cookie_name=os.getenv("AUTHCENTRAL_COOKIE_NAME", "authcentral_session"),
            cookie_domain=os.getenv("AUTHCENTRAL_COOKIE_DOMAIN") or None,
            cookie_secure=secure_value in {"true", "1", "yes"},
            session_ttl_seconds=int(os.getenv("AUTHCENTRAL_SESSION_TTL_SECONDS", "3600")),
            issuer=os.getenv("AUTHCENTRAL_ISSUER", "authcentral"),
            audience=os.getenv("AUTHCENTRAL_AUDIENCE", "authcentral-app"),
        )
