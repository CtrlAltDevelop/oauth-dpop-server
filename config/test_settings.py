"""Settings for the test suite and the type checker.

A throwaway secret is supplied when the environment has none, so the suite and
``mypy`` run on a fresh checkout. The database still comes from
``DATABASE_URL`` when it is set — CI points it at Postgres.
"""

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "test-only-not-a-real-key")

from config.settings import *  # noqa: F403

# The suite's cost is dominated by password hashing on user fixtures.
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]

OAUTH_ISSUER = "https://auth.example.test"
ALLOWED_HOSTS = ["testserver", "auth.example.test"]
