1. Цель продукта

Быстро и автоматически удалять “эротический” спам в Telegram‑группах стартап‑сообщества, снижая визуальный шум до 0 (OKR‑1) и экономя модераторам ≥ 2 ч/нед (OKR‑2).

⸻

2. Область (Scope)

Раздел	Включено v1.0	Исключено v1.0
Группы	Публичные/приватные супер‑группы до 10 000 участников	Каналы, личные чаты
Спам‑тип	Erotica‑link‑трафик, как в описании	Фишинг, замаскированный рекламо‑бот
Классификация NSFW	Локальный NudeNet 2.0 lite	Cloud Vision, CLIP
LLM	GPT‑4o‑mini через OpenAI API	Самостоятельный хостинг LLM
Язык сообщений	RU, UA, EN	Мультиязычное расширение > 3 языков



⸻

3. Пользовательские сценарии (User Stories)
	1.	US‑01: Как администратор чата, я хочу, чтобы бот удалял эротический спам и банил автора, чтобы участники не видели нежелательный контент.
	2.	US‑02: Как администратор, я хочу отчёт /stats с числом предотвращённых сообщений за период, чтобы понимать эффективность.
	3.	US‑03: Как администратор, я хочу временно выключать бота /toggle, чтобы тестировать без банов.

⸻

4. Бизнес‑правила / Алгоритм
	1.	Триггер: любое новое текстовое сообщение message в группе.
	2.	Сбор фич:
	•	bio = user.bio or "" — проверка RegExp r"https?://|t\.me/".
	•	avatar_unsafe = NudeNet(img) > 0.7.
	•	Если (link_in_bio AND avatar_unsafe) == False → выход (Safe).
	3.	LLM‑оценка:

PROMPT:
Determine if the profile is erotic spam (0‑not, 1‑spam).
Name: {first_name}
Bio: {bio}
Message: {msg_text}

	•	Ответ 1? → ban_chat_member, delete_message.
	•	Ответ 0? → игнор.

	4.	Логирование: запись результата + latency в PostgreSQL.

⸻

5. Архитектура (минимальная)

┌─────────┐   HTTPS   ┌───────────────┐
│Telegram │──────────▶│ FastAPI bot   │
└─────────┘  webhook  │  (uvicorn)    │
                     │  │            │
                     │  ├──> NudeNet │(onnx)
                     │  └──> OpenAI  │(HTTP)
                     └───────────────┘
                       │  logs
                       ▼
                   PostgreSQL

Один контейнер bot содержит всё, NudeNet работает через ONNXRuntime CPU.

⸻

6. API‑контракты

Endpoint	Method	Auth	Функция
/webhook	POST	Telegram	Приём Update
/stats	GET 	Admin JWT	JSON {"spam_removed": int,"period": "ISO‑date"}
/toggle	POST	Admin JWT	Body {"enabled": bool}



⸻

7. Полный Dockerfile
```dockerfile
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
```

pyproject.toml (зависимости без пропусков)

```
[tool.poetry]
name = "antieroticspam"
version = "1.0.0"
description = "Telegram anti‑erotic‑spam bot"
authors = ["Team"]
[tool.poetry.dependencies]
python = "^3.12"
python-telegram-bot = "^22.4"
fastapi = "^0.111.0"
uvicorn = {extras = ["standard"], version = "^0.29.0"}
nudenet = "^2.0.1"
pillow = "^10.3.0"
opencv-python = "^4.10.0.82"
openai = "^1.25.0"
asyncpg = "^0.29.0"
python-multipart = "^0.0.9"
python-dotenv = "^1.0.1"
```
docker-compose.yml

version: "3.9"
services:
  bot:
    build: .
    env_file: .env
    ports:
      - "8000:8000"
    depends_on:
      - db
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: spamdb
      POSTGRES_USER: spamuser
      POSTGRES_PASSWORD: spampass
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  pgdata:



⸻

8. Переменные окружения (.env, все требуются)
```env
TG_TOKEN=123456:ABC...
OPENAI_KEY=sk-...
ADMIN_IDS=123456789,987654321
WEBHOOK_URL=https://your-domain.com/webhook
POSTGRES_DSN=postgresql+asyncpg://spamuser:spampass@db/spamdb
```


⸻

9. Метрики успеха

KPI	Цель v1	Метод измерения
FP Rate (ложные баны)	≤ 1 %	ручная ревизия журнала
Spam Throughput (неудалённые)	≤ 1/1000 сообщений	cron‑SQL
Latency удаления	≤ 3 с p95	Prometheus histogram
SLA аптайма	99.5 %	UptimeRobot



⸻

10. План выпуска

Этап	Срок	Выход
Тех.‑дизайн	 День 1	PRD (настоящий)
POC локально	 День 2	docker run + тест‑чат
Beta‑роллаут	 День 3	Группа “QA” 200 участников
Prod v1.0	 День 5	Публичные сообщества



⸻

11. Риски и меры

Риск	Вероятность	Влияние	Митиг.
Rate‑limit Telegram на getUserProfilePhotos	Средняя	Умеренно	кеширование avatar‑hash
Подмена SFW‑аватара после вступления	Низкая	Средняя	повторная проверка при новом msg
Дороговизна GPT‑4o	Средняя	Высокая	фильтр “link+unsafe” уменьшает вызовы на ≈ 95 %
FP‑бан реальных пользователей	Низкая	Высокая	mute 1 мин вместо бана в beta



⸻

12. Будущие улучшения (v1.1+)
	•	CLIP‑вектор + K‑NN для семантической бессмысленности без LLM.
	•	Greylist с повторной проверкой через 2 дня.
	•	Панель админа на Next.js c live‑логами.

⸻

PRD завершён, содержит полные файлы без пропусков. Готов к передаче разработчику и DevOps‑инженеру.