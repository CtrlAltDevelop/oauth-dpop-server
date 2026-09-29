.PHONY: install lint format typecheck test test-postgres interop check requirements run migrate keys up down

install:            ## Install every dependency group into .venv
	uv sync --all-groups

lint:               ## Lint and check formatting
	uv run ruff check .
	uv run ruff format --check .

format:             ## Apply formatting and safe lint fixes
	uv run ruff format .
	uv run ruff check --fix .

typecheck:          ## mypy --strict with the Django plugin
	uv run mypy .

test:               ## The test suite (SQLite and fakeredis; no services needed)
	uv run pytest

test-postgres:      ## The test suite against Postgres at $$DATABASE_URL
	DATABASE_URL=$${DATABASE_URL:-postgres://oauth:oauth@localhost:5432/oauth} uv run pytest

interop:            ## Dart dpop_client against a live server (needs Dart, Redis, ../dpop_client)
	scripts/interop.sh

check: lint typecheck test   ## Everything CI runs, locally

requirements:       ## Regenerate requirements.txt from uv.lock (CI installs from it)
	uv export --format requirements-txt --all-groups --no-emit-project --quiet -o requirements.txt

migrate:
	DJANGO_DEBUG=true uv run python manage.py migrate

run: migrate        ## Development server on :8000 (needs Redis at $$REDIS_URL)
	DJANGO_DEBUG=true uv run python manage.py runserver

keys:               ## Rotate signing keys: pending -> active -> retired
	DJANGO_DEBUG=true uv run python manage.py rotate_signing_keys

up:                 ## Server, Postgres and Redis in Docker
	docker compose up --build -d

down:
	docker compose down
