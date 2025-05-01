# Anti-Erotic-Spam Telegram Bot

This repository implements a Telegram bot that automatically removes erotic spam from group chats.

## Features

- **Profile Analysis**: Checks for links in user bios and analyzes profile pictures
- **Image Detection**: Uses NudeNet to detect NSFW content in avatars
- **Text Classification**: Employs OpenAI's GPT-4o-mini to identify spam messages
- **Database Logging**: Records all actions in PostgreSQL
- **Metrics**: Prometheus metrics for monitoring bot performance

## Prerequisites
- Docker & Docker Compose
- Or Python 3.12 (exact) and Poetry
  (Python 3.13 is not supported due to some C-extension incompatibilities)

## Environment Variables

Create a `.env` file with the following variables:

```
# Telegram Bot Token from BotFather
TG_TOKEN=your_telegram_bot_token

# OpenAI API Key
OPENAI_KEY=your_openai_api_key

# Comma-separated list of admin Telegram user IDs
ADMIN_IDS=123456789,987654321

# Public URL for Telegram webhook
WEBHOOK_URL=https://your-domain.com/webhook

# Secret token for Telegram webhook validation
WEBHOOK_SECRET=your_webhook_secret

# PostgreSQL connection string
POSTGRES_DSN=postgresql://user:password@postgres:5432/bot

# Secret key for JWT token generation
JWT_SECRET=your_jwt_secret

# OpenAI model to use (default: gpt-4o-mini)
OPENAI_MODEL=gpt-4o-mini

# Log level (default: info)
LOG_LEVEL=info

# Avatar cache TTL in seconds (default: 3600)
AVATAR_CACHE_TTL=3600

# JWT token expiration in seconds (default: 86400)
JWT_EXPIRATION=86400
```

## Getting Started
1. Copy `.env.template` to `.env` and fill in the required environment variables.
   Make sure `POSTGRES_DSN` uses the format `postgresql://user:pass@host/db`, not SQLAlchemy's `postgresql+asyncpg://`.
Ensure you are running under Python 3.12 (e.g., with `pyenv` or similar) before proceeding.
> **MacOS users:** asyncpg currently has no prebuilt wheels for macOS on Python 3.12, so local installs may fail with build errors.
> You can:
> 1. Downgrade your local interpreter to Python 3.11 for development.
> 2. Skip local host install and instead use Docker Compose (`docker-compose up --build`), which uses a Linux environment with available asyncpg wheels.
2. Install dependencies (optional, for local dev):

   ```
   poetry install
   ```

3. Generate `poetry.lock`:

   ```
   poetry lock
   ```

4. Run locally:

   ```
   poetry run start
   ```

5. Build and run with Docker Compose:

   ```
   docker-compose up --build
   ```

6. To generate an admin JWT token:

   ```
   python scripts/gen_token.py <ADMIN_ID> [EXPIRATION_SECONDS]
   ```

## Project Structure

```
bot/
├── __init__.py
├── main.py                # Main FastAPI application
├── avatar_analyzer.py     # Avatar analysis with NudeNet
├── spam_classifier.py     # Text classification with OpenAI
├── auth.py                # JWT authentication
├── database.py            # Database operations
├── telegram_utils.py      # Telegram API utilities
└── metrics.py             # Prometheus metrics
```

## Endpoints

- `/webhook` [POST]: Telegram webhook handler.
- `/stats` [GET]: Returns JSON with spam removed (requires Bearer JWT).
- `/toggle` [POST]: Enable/disable bot (requires Bearer JWT).

## Security Features

- **JWT Authentication**: Secure admin endpoints with JWT tokens
- **Webhook Validation**: Validate that requests come from Telegram
- **Temporary File Handling**: Proper cleanup of temporary files

## Performance Optimizations

- **Avatar Caching**: Cache avatar analysis results to reduce API calls
- **Connection Pooling**: Efficient database connection management
- **Metrics Collection**: Monitor performance with Prometheus metrics