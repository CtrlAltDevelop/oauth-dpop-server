"""Settings for the authorization server.

Everything that differs between environments is read from the environment,
and nothing secret has a production default: an unset ``DJANGO_SECRET_KEY``
is a startup error unless ``DJANGO_DEBUG`` is on.
"""

import os
from pathlib import Path

import dj_database_url
import django_stubs_ext
from django.core.exceptions import ImproperlyConfigured

# Lets generic Django classes (ModelAdmin[Client], QuerySet[Token]) be
# subscripted at runtime, as they already are for the type checker.
django_stubs_ext.monkeypatch()

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


DEBUG = _env_bool("DJANGO_DEBUG", False)

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set when DJANGO_DEBUG is off.")
    SECRET_KEY = "dev-only-insecure-secret-key-do-not-deploy"

ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "authserver",
    "demo_api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"

DATABASES = {
    "default": dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=60,
    ),
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

LOGIN_URL = "authserver:login"

# --- Transport and browser hardening --------------------------------------
# The consent page is the one screen an attacker most wants to frame.
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "no-referrer"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = _env_bool("DJANGO_SECURE_SSL_REDIRECT", False)
if _env_bool("DJANGO_BEHIND_TLS_PROXY", False):
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

# --- Authorization server (see authserver/conf.py for every knob) ---------
OAUTH_ISSUER = os.environ.get("OAUTH_ISSUER", "http://localhost:8000")
# Private signing keys are encrypted with a key derived from this. Separate
# from SECRET_KEY so rotating one does not orphan the other.
OAUTH_KEY_ENCRYPTION_SECRET = os.environ.get("OAUTH_KEY_ENCRYPTION_SECRET", SECRET_KEY)


def resource_server(issuer: str) -> dict[str, object]:
    """``NINJA_DPOP`` for the example API, which shares this process."""
    return {
        "ISSUER": issuer,
        "AUDIENCE": f"{issuer}/api",
        "ORIGIN": issuer,
        # In-process, so the keys are read straight from the database. A
        # separate resource server would use f"{issuer}/oauth/jwks".
        "JWKS": "authserver.keys.published_jwks",
        "REDIS": "authserver.redis.get_redis",
    }


NINJA_DPOP = resource_server(OAUTH_ISSUER)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {
        "authserver": {"handlers": ["console"], "level": os.environ.get("LOG_LEVEL", "INFO")},
    },
}
