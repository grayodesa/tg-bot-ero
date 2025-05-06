# Anti-Erotic-Spam Telegram Bot

This repository implements a Telegram bot that automatically removes erotic spam from group chats using AI content moderation. The bot analyzes new members' first messages, profile pictures, and bios to detect and remove spam messages.

## Features

- **Multi-level Spam Detection**:
  - **Profile Analysis**: Checks for links in user bios and analyzes profile pictures
  - **Image Detection**: Uses NudeNet to detect NSFW content in avatars
  - **Text Classification**: Employs OpenAI's GPT-4o-mini to identify spam messages
- **Reliable Architecture**:
  - **FastAPI Backend**: Modern asynchronous framework with OpenAPI documentation
  - **Docker Containerization**: Easy deployment with Docker Compose
  - **Graceful Shutdown**: Proper handling of SIGTERM signals
  - **Health Checks**: Built-in health endpoints for monitoring
- **Performance Optimizations**:
  - **Redis Caching**: Efficient caching of analysis results with Redis
  - **In-memory Fallback**: Continues working when Redis is unavailable
  - **Database Indexes**: Optimized PostgreSQL queries
  - **Connection Pooling**: Efficient database and HTTP connection management
- **Comprehensive Monitoring**:
  - **Prometheus Metrics**: Detailed performance and operational metrics
  - **Admin Dashboard**: Web interface for monitoring and control
  - **Database Logging**: Records all actions in PostgreSQL

## Prerequisites

- Docker & Docker Compose (recommended)
- Or Python 3.12 (exact) and Poetry
  (Python 3.13 is not supported due to some C-extension incompatibilities)
- PostgreSQL database
- Redis (optional, for improved caching)

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

# JWT refresh token expiration in seconds (default: 604800)
JWT_REFRESH_EXPIRATION=604800

# Redis URL for caching (optional)
REDIS_URL=redis://redis:6379/0

# Rate limit for webhook (requests per minute)
WEBHOOK_RATE_LIMIT=60

# Temporary files directory
TEMP_DIR=/tmp
```

## Getting Started

1. Copy `.env.template` to `.env` and fill in the required environment variables.
   Make sure `POSTGRES_DSN` uses the format `postgresql://user:pass@host/db`, not SQLAlchemy's `postgresql+asyncpg://`.

> **Note for MacOS users:** asyncpg currently has no prebuilt wheels for macOS on Python 3.12, so local installs may fail with build errors.
> You can:
> 1. Downgrade your local interpreter to Python 3.11 for development.
> 2. Skip local host install and instead use Docker Compose (`docker-compose up --build`), which uses a Linux environment with available asyncpg wheels.

2. **Docker Method (Recommended)**:
   Build and run with Docker Compose:

   ```
   docker-compose up --build
   ```

3. **Local Development Method**:
   Install dependencies (optional, for local dev):

   ```
   poetry install
   ```

   Generate `poetry.lock` if it doesn't exist:

   ```
   poetry lock
   ```

   Run locally:

   ```
   poetry run start
   ```

4. **Generate Admin JWT Tokens**:
   For admin access, generate both access and refresh tokens:

   ```
   python scripts/gen_token.py <ADMIN_ID>
   ```

   This will generate both an access token (24 hour validity) and a refresh token (7 day validity).

## Project Structure

```
bot/
├── __init__.py
├── main.py                # Main FastAPI application
├── admin/                 # Admin dashboard and management
│   ├── __init__.py
│   ├── router.py          # Admin API routes
│   └── templates/         # Jinja2 templates for dashboard
├── services/              # Business logic services
│   ├── __init__.py
│   └── spam_detector.py   # Spam detection service
├── utils/                 # Utility functions
│   ├── __init__.py
│   └── file_utils.py      # Secure file handling utilities
├── avatar_analyzer.py     # Avatar analysis with NudeNet
├── spam_classifier.py     # Text classification with OpenAI
├── security.py            # Enhanced security with PyJWT
├── cache.py               # Redis and in-memory caching
├── database.py            # Database operations with indexes
├── telegram_utils.py      # Telegram API utilities
└── metrics.py             # Prometheus metrics
```

## API Endpoints

### Public Endpoints
- `/webhook` [POST]: Telegram webhook handler (rate-limited).
- `/health` [GET]: Health check endpoint for monitoring.

### Authentication Endpoints
- `/refresh-token` [POST]: Generate new access token using refresh token.

### Admin Endpoints (requires JWT)
- `/stats` [GET]: Returns JSON with spam statistics.
- `/toggle` [POST]: Enable/disable bot.
- `/admin/dashboard` [GET]: Web dashboard for statistics and control.

## Security Features

- **PyJWT Authentication**: Industry-standard JWT implementation
- **Refresh Tokens**: Secure token refresh mechanism
- **Rate Limiting**: Protection against abuse on webhook endpoint
- **Webhook Validation**: Telegram-specific request validation
- **Secure File Handling**: Context managers ensure file cleanup
- **CORS and Middleware**: Security-related HTTP headers
- **Database Connection Pooling**: Secure database access patterns

## Performance Optimizations

- **Redis Caching**: Primary cache with TTL support
- **In-memory Fallback**: Local cache when Redis is unavailable
- **NudeNet Singleton**: Optimize model loading and initialization
- **Database Indexes**: Multiple indexes for query optimization
- **Connection Pooling**: Efficient resource management
- **GZip Compression**: Middleware for response compression
- **Metrics Collection**: Monitor performance with Prometheus

## Docker Configuration

The project includes a multi-stage Docker build for efficient container images and a Docker Compose configuration for easy deployment with PostgreSQL and Redis:

- **Health Checks**: Container health monitoring for all services
- **Graceful Shutdown**: Signal handling for clean termination
- **Volume Persistence**: Data persistence for database and Redis
- **Resource Management**: Configurable resource limits

## Admin Dashboard and Monitoring

### Admin Dashboard

Access the admin dashboard at `/admin/dashboard` using a valid JWT token. The dashboard provides:

- Real-time statistics on spam detection
- Bot control panel (enable/disable)
- Performance metrics

To access the dashboard:
1. Generate an access token using the `gen_token.py` script:
   ```
   python scripts/gen_token.py <YOUR_ADMIN_ID>
   ```
2. Use the token with an HTTP client (like curl) by setting the Authorization header:
   ```
   curl -H "Authorization: Bearer <YOUR_TOKEN>" http://your-bot-domain.com/admin/dashboard
   ```
   Or simply visit `/admin/dashboard` in your browser and provide the token when prompted.

### Prometheus and Grafana Monitoring

The project includes a complete monitoring stack with Prometheus and Grafana:

1. Start the monitoring stack:
   ```
   docker-compose -f docker-compose.monitoring.yml up -d
   ```

2. Access Grafana dashboards:
   - URL: http://localhost:3000
   - Default login: admin/admin
   - A pre-configured dashboard for the bot is available under "Dashboards"

3. Access Prometheus directly:
   - URL: http://localhost:9090
   - Use the Prometheus UI to query metrics and check alert status

4. AlertManager for alert management:
   - URL: http://localhost:9093
   - Configure notifications by editing `monitoring/alertmanager.yml`

The monitoring stack provides:
- Real-time metrics visualization
- Performance tracking
- Alerts for critical conditions
- Historical data analysis

## License

This project is licensed under the terms of the MIT license.