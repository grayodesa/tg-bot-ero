# Anti-Erotic-Spam Telegram Bot

This repository implements a Telegram bot that automatically removes erotic spam from group chats.

## Prerequisites
- Docker & Docker Compose
- Or Python 3.12 (exact) and Poetry
  (Python 3.13 is not supported due to some C-extension incompatibilities)

## Getting Started
1. Copy `.env.template` to `.env` and fill in the required environment variables.
   Make sure `POSTGRES_DSN` uses the format `postgresql://user:pass@host/db`, not SQLAlchemy’s `postgresql+asyncpg://`.
Ensure you are running under Python 3.12 (e.g., with `pyenv` or similar) before proceeding.
> **MacOS users:** asyncpg currently has no prebuilt wheels for macOS on Python 3.12, so local installs may fail with build errors.
> You can:
> 1. Downgrade your local interpreter to Python 3.11 for development.
> 2. Skip local host install and instead use Docker Compose (`docker-compose up --build`), which uses a Linux environment with available asyncpg wheels.
2. Install dependencies (optional, for local dev):

   poetry install

3. Generate `poetry.lock`:

   poetry lock

4. Run locally:

   poetry run start

5. Build and run with Docker Compose:

   docker-compose up --build

6. To generate an admin JWT token:

   python scripts/gen_token.py <ADMIN_ID>

## Endpoints
- `/webhook` [POST]: Telegram webhook handler.
- `/stats` [GET]: Returns JSON with spam removed (requires Bearer JWT).
- `/toggle` [POST]: Enable/disable bot (requires Bearer JWT).