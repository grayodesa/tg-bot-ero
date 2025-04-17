# Anti-Erotic-Spam Telegram Bot

This repository implements a Telegram bot that automatically removes erotic spam from group chats.

## Prerequisites
 - Docker & Docker Compose
 - Or Python 3.12+ and Poetry

## Getting Started
1. Copy `.env.template` to `.env` and fill in the required environment variables.
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