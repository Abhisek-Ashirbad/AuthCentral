import argparse
import secrets
import sys
from pathlib import Path
from typing import Callable

from .config import AuthConfig


def _ask(
    prompt: str,
    default: str,
    input_fn: Callable[[str], str],
) -> str:
    answer = input_fn(f"{prompt} [{default}]: ").strip()
    return answer or default


def create_config(
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
) -> AuthConfig:
    secret = input_fn("Signing secret (leave blank to generate a secure key) [generated]: ").strip()
    if not secret:
        secret = secrets.token_urlsafe(48)
    prefix = _ask("Authentication URL prefix", "/auth", input_fn)
    cookie_name = _ask("Session cookie name", "authcentral_session", input_fn)
    cookie_domain = _ask("Cookie domain (blank for host-only cookie)", "", input_fn) or None
    secure_value = _ask("Require HTTPS for the cookie? (true/false)", "false", input_fn).lower()
    if secure_value not in {"true", "false"}:
        raise ValueError("Cookie secure setting must be true or false")
    ttl_value = _ask("Session lifetime in seconds", "3600", input_fn)
    try:
        ttl = int(ttl_value)
    except ValueError as error:
        raise ValueError("Session lifetime must be a positive whole number of seconds") from error

    config = AuthConfig(
        secret_key=secret,
        auth_prefix=prefix,
        cookie_name=cookie_name,
        cookie_domain=cookie_domain,
        cookie_secure=secure_value == "true",
        session_ttl_seconds=ttl,
    )
    output_fn("Configuration collected. Blank answers use the displayed defaults.")
    return config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create an AuthCentral configuration file.")
    parser.add_argument("--output", type=Path, default=Path("authcentral.toml"))
    args = parser.parse_args(argv)

    if args.output.exists():
        print(f"Refusing to overwrite existing configuration: {args.output}", file=sys.stderr)
        return 1
    try:
        config = create_config()
        args.output.write_text(config.to_toml(), encoding="utf-8")
    except (OSError, ValueError) as error:
        print(f"Could not create configuration: {error}", file=sys.stderr)
        return 1

    print(f"Configuration written to {args.output}")
    print("Load it in your app with AuthConfig.from_toml() and include AuthCentral(config).router.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
