# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Run the bot locally: `poetry run start`
- Install dependencies: `poetry install`
- Update lockfile: `poetry lock`
- Build and run with Docker: `docker-compose up --build`
- Generate admin token: `python scripts/gen_token.py <ADMIN_ID>`
- Run tests: `poetry run test` or `python -m pytest tests/`

## Code Guidelines

- Python version: Use Python 3.12 only (asyncpg compatibility)
- Indentation: 4 spaces
- Type hints: Use typing annotations for function parameters and returns
- Imports: Group standard library, third-party, and local imports with blank lines
- Error handling: Use try/except blocks with specific exceptions and logging
- Naming: Follow PEP 8 (snake_case for variables/functions, UPPER_CASE for constants)
- Docstrings: Use triple quotes for module/function docstrings
- Environment: Use config.py and dotenv for configuration
- Logging: Use the logging module with appropriate log levels