# -------- ПЕРВАЯ СТАДИЯ: build --------
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

# -------- ВТОРАЯ СТАДИЯ: runtime --------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
        libjpeg62-turbo \
        libpng16-16 \
        libgl1-mesa-glx \
        libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*
    # Create non-root 'bot' user
RUN useradd -ms /bin/bash bot

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app
USER bot
WORKDIR /app

ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    LOG_LEVEL=info

EXPOSE 8000
# Launch using uvicorn directly rather than poetry run
CMD ["uvicorn", "bot.main:app", "--host", "0.0.0.0", "--port", "8000", "--log-level", "info"]