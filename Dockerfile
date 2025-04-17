# -------- ПЕРВАЯ СТАДИЯ: build --------
FROM python:3.12-slim AS builder

ENV POETRY_VERSION=1.8.2 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential git wget ca-certificates && \
    pip install --no-cache-dir poetry==$POETRY_VERSION && \
    useradd -ms /bin/bash bot

WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --only main

# -------- ВТОРАЯ СТАДИЯ: runtime --------
FROM python:3.12-slim

RUN apt-get update && apt-get install -y libjpeg62-turbo libpng16-16 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local
COPY --from=builder /app /app
USER bot
WORKDIR /app

ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8000 \
    LOG_LEVEL=info

EXPOSE 8000
CMD ["poetry", "run", "python", "-m", "bot.main"]