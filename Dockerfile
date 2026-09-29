# syntax=docker/dockerfile:1
FROM python:3.14-slim AS build

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM python:3.14-slim

ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --create-home --home-dir /app app
WORKDIR /app
COPY --from=build /opt/venv /opt/venv
COPY --chown=app:app manage.py ./
COPY --chown=app:app config ./config
COPY --chown=app:app authserver ./authserver
COPY --chown=app:app dpop ./dpop
COPY --chown=app:app ninja_dpop ./ninja_dpop
COPY --chown=app:app demo_api ./demo_api

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/.well-known/oauth-authorization-server', timeout=2)"
CMD ["gunicorn", "config.wsgi", "--bind", "0.0.0.0:8000", "--workers", "3", "--access-logfile", "-"]
