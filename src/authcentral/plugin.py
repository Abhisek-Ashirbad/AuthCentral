from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

import jwt
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .config import AuthConfig
from .store import InMemoryUserStore, UserStore


@dataclass(frozen=True)
class AuthUser:
    username: str


class AuthCentral:
    def __init__(self, config: AuthConfig | None = None, user_store: UserStore | None = None) -> None:
        self.config = config or AuthConfig.from_env()
        self.user_store = user_store or InMemoryUserStore()
        self.router = APIRouter(prefix=self.config.auth_prefix, tags=["authentication"])
        self.templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
        self._register_routes()

    def _register_routes(self) -> None:
        @self.router.get("/", response_class=HTMLResponse, name="auth_login_page")
        def login_page(request: Request, error: str | None = None):
            return self.templates.TemplateResponse(
                request=request,
                name="login.html",
                context={"error": error},
            )

        @self.router.post("/signup", name="auth_signup")
        def signup(
            username: str = Form(..., min_length=1, max_length=64),
            password: str = Form(..., min_length=8, max_length=1024),
        ):
            normalized_username = username.strip()
            if not normalized_username:
                return RedirectResponse(url=f"{self.config.auth_prefix}/?error=Username+is+required", status_code=303)
            if not self.user_store.create(normalized_username, password):
                return RedirectResponse(url=f"{self.config.auth_prefix}/?error=User+already+exists", status_code=303)
            return RedirectResponse(
                url=f"{self.config.auth_prefix}/?error=Account+created.+Please+sign+in.",
                status_code=303,
            )

        @self.router.post("/signin", name="auth_signin")
        def signin(
            username: str = Form(..., min_length=1, max_length=64),
            password: str = Form(..., min_length=8, max_length=1024),
            next: str = Form("/", max_length=2048),
        ):
            normalized_username = username.strip()
            user = self.user_store.verify(normalized_username, password)
            if user is None:
                return RedirectResponse(
                    url=f"{self.config.auth_prefix}/?error=Invalid+credentials",
                    status_code=303,
                )

            now = datetime.now(timezone.utc)
            token = jwt.encode(
                {
                    "sub": user.username,
                    "iat": now,
                    "exp": now + timedelta(seconds=self.config.session_ttl_seconds),
                    "iss": self.config.issuer,
                    "aud": self.config.audience,
                },
                self.config.secret_key,
                algorithm="HS256",
            )
            response = RedirectResponse(url=self._safe_redirect(next), status_code=303)
            response.set_cookie(
                key=self.config.cookie_name,
                value=token,
                domain=self.config.cookie_domain,
                httponly=True,
                secure=self.config.cookie_secure,
                samesite="lax",
                max_age=self.config.session_ttl_seconds,
            )
            return response

        @self.router.post("/logout", name="auth_logout")
        def logout():
            response = RedirectResponse(url=f"{self.config.auth_prefix}/", status_code=303)
            response.delete_cookie(
                key=self.config.cookie_name,
                domain=self.config.cookie_domain,
                path="/",
                secure=self.config.cookie_secure,
                httponly=True,
                samesite="lax",
            )
            return response

    @staticmethod
    def _safe_redirect(target: str) -> str:
        parsed = urlsplit(target)
        if (
            target.startswith("/")
            and not target.startswith("//")
            and "\\" not in target
            and not parsed.scheme
            and not parsed.netloc
        ):
            return target
        return "/"

    async def get_current_user(self, request: Request) -> AuthUser:
        token = request.cookies.get(self.config.cookie_name)
        if not token:
            raise HTTPException(
                status_code=401,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            payload = jwt.decode(
                token,
                self.config.secret_key,
                algorithms=["HS256"],
                issuer=self.config.issuer,
                audience=self.config.audience,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.InvalidTokenError as error:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired session",
                headers={"WWW-Authenticate": "Bearer"},
            ) from error

        username = payload.get("sub")
        if not isinstance(username, str) or not username:
            raise HTTPException(status_code=401, detail="Invalid session subject")
        return AuthUser(username=username)
