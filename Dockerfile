# -------- FIRST STAGE: build --------
FROM python:3.12-slim AS builder

ENV POETRY_VERSION=1.8.2 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git wget ca-certificates && \
    pip install --no-cache-dir poetry==$POETRY_VERSION && \
    useradd -ms /bin/bash bot

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --only main
# Copy application source code into builder for packaging
COPY . .

# -------- SECOND STAGE: runtime --------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
        libjpeg62-turbo \
        libpng16-16 \
        libgl1-mesa-glx \
        libglib2.0-0 \
        curl \
    && rm -rf /var/lib/apt/lists/*
    # Create non-root 'bot' user
RUN useradd -ms /bin/bash bot

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app
USER bot
WORKDIR /app

ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    LOG_LEVEL=info \
    PYTHONPATH=/app

# Health check using curl
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

# Use a script for graceful shutdown
COPY --chown=bot:bot docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

# Launch using the entrypoint script
CMD ["/app/docker-entrypoint.sh"]