"""Configuration, read from environment variables.

Secrets (master key, audit key) are required in production; the app refuses
to start without them rather than silently falling back to a default.
"""
import base64
import json
import os
import secrets


class ConfigError(RuntimeError):
    pass


def load_dotenv(path: str | None = None):
    """Read KEY=VALUE lines from .env in the project root (if present) into the
    environment, without overriding anything already set. One file then serves
    the web app, the seed script and the maintenance scripts alike."""
    path = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_dotenv()


def _dev_key(name: str, db_path: str) -> bytes:
    """Development only: keep generated keys in a file next to the database so
    the app can restart without losing the ability to decrypt files."""
    path = os.path.join(os.path.dirname(os.path.abspath(db_path)), "dev_keys.json")
    keys = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            keys = json.load(f)
    if name not in keys:
        keys[name] = generate_key_b64()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(keys, f)
        os.chmod(path, 0o600)
    return base64.b64decode(keys[name])


def _key_from_env(name: str, required: bool, db_path: str) -> bytes:
    raw = os.environ.get(name)
    if not raw:
        if required:
            raise ConfigError(
                f"{name} is not set. Generate one with: "
                "python -c \"import secrets,base64;print(base64.b64encode(secrets.token_bytes(32)).decode())\""
            )
        return _dev_key(name, db_path)
    key = base64.b64decode(raw)
    if len(key) != 32:
        raise ConfigError(f"{name} must be 32 bytes, base64-encoded")
    return key


class Config:
    def __init__(self, **overrides):
        env = os.environ.get("TV_ENV", "development")
        self.ENV = overrides.get("ENV", env)
        is_prod = self.ENV == "production"

        self.DATABASE_PATH = overrides.get(
            "DATABASE_PATH", os.environ.get("TV_DATABASE_PATH", "instance/trustvault.db")
        )
        self.MASTER_KEY = overrides.get("MASTER_KEY") or _key_from_env("TV_MASTER_KEY", is_prod, self.DATABASE_PATH)
        self.AUDIT_KEY = overrides.get("AUDIT_KEY") or _key_from_env("TV_AUDIT_KEY", is_prod, self.DATABASE_PATH)
        if self.MASTER_KEY == self.AUDIT_KEY:
            raise ConfigError("TV_MASTER_KEY and TV_AUDIT_KEY must be different keys")

        # Cookies are Secure (HTTPS-only) everywhere except local development.
        self.SECURE_COOKIES = overrides.get(
            "SECURE_COOKIES", os.environ.get("TV_SECURE_COOKIES", "1" if is_prod else "0") == "1"
        )
        # Behind exactly one reverse proxy (PythonAnywhere / Render / Fly) set to 1
        self.TRUSTED_PROXIES = int(overrides.get("TRUSTED_PROXIES", os.environ.get("TV_TRUSTED_PROXIES", "0")))

        self.SESSION_IDLE_MINUTES = int(overrides.get("SESSION_IDLE_MINUTES", 30))
        self.SESSION_ABSOLUTE_HOURS = int(overrides.get("SESSION_ABSOLUTE_HOURS", 8))

        self.MAX_UPLOAD_BYTES = int(overrides.get("MAX_UPLOAD_BYTES", 10 * 1024 * 1024))

        self.LOGIN_MAX_FAILURES = int(overrides.get("LOGIN_MAX_FAILURES", 5))
        self.LOGIN_LOCK_MINUTES = int(overrides.get("LOGIN_LOCK_MINUTES", 15))
        self.LOGIN_RATE_PER_IP = int(overrides.get("LOGIN_RATE_PER_IP", 20))  # per 5 minutes

        self.TRASH_RETENTION_DAYS = int(overrides.get("TRASH_RETENTION_DAYS", 30))

        # In demo mode, seeded accounts cannot change their own password, so
        # one judge cannot lock the others out of the shared demo accounts.
        self.DEMO_MODE = overrides.get("DEMO_MODE", os.environ.get("TV_DEMO_MODE", "0") == "1")

        self.TESTING = overrides.get("TESTING", False)

    @property
    def cookie_name(self) -> str:
        # The __Host- prefix makes the browser refuse the cookie unless it is
        # Secure, has Path=/ and no Domain - so a sibling subdomain cannot set it.
        return "__Host-tv_session" if self.SECURE_COOKIES else "tv_session"


def generate_key_b64() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()
