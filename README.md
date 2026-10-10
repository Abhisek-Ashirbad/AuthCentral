# AuthCentral

AuthCentral is a reusable username/password authentication plugin for FastAPI applications. It provides account registration, sign-in, logout, and a signed HTTP-only session cookie. It does not currently authenticate with Google.

## Install and configure

Install the project in the same Python environment as your FastAPI app:

```shell
python -m pip install -e .
python -m authcentral.setup
```

The setup command interactively asks for the auth URL prefix, cookie name/domain/security, and session duration. Press Enter at any prompt to accept its default. A cryptographically random signing key is generated when its prompt is left blank. The command writes these settings to `authcentral.toml` and will not overwrite an existing file. Keep that file private and out of version control.

## Integrate with a FastAPI application

Load the config generated during setup, include the plugin router, and protect routes with its authentication dependency:

```python
from fastapi import Depends, FastAPI
from authcentral import AuthCentral, AuthConfig, AuthUser

app = FastAPI()
auth = AuthCentral(config=AuthConfig.from_toml("authcentral.toml"))
app.include_router(auth.router)

@app.get("/private")
async def private_page(user: AuthUser = Depends(auth.get_current_user)):
    return {"message": f"Hello, {user.username}"}
```

Users can register and sign in at `/auth/` with the default prefix. After login, they return to the relative path sent as the `next` form field; invalid or external redirect targets fall back to `/`. Protected endpoints return HTTP 401 if no valid session cookie is present. For browser-facing protected pages, redirect to the configured sign-in page when handling that response.

## Authentication behavior and limitations

- Passwords are salted and derived with PBKDF2-HMAC-SHA256; passwords are never stored in plaintext.
- JWT sessions expire and are checked for signature, issuer, audience, and required claims.
- Use `Depends(auth.get_current_user)` to protect a route and `POST /auth/logout` to clear the session.
- The default `InMemoryUserStore` is for development only; users are lost on restart. Production apps should pass a persistent implementation of the `UserStore` interface to `AuthCentral`.
- Use HTTPS and `cookie_secure=true` in production. Leave the cookie domain blank for host-only cookies, or set it to a shared parent domain when your app spans subdomains.
- For non-interactive setup, configure an `AuthConfig` directly or use the `AUTHCENTRAL_*` environment variables supported by `AuthConfig.from_env()`.

## Tests

Run the tests from the repository root:

```shell
python -m unittest discover -s tests -v
```
