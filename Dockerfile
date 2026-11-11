FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir --no-deps .

ENV PYTHONUNBUFFERED=1
ENV HOST=0.0.0.0
ENV PORT=8765
ENV COGNIGUARD_DB_PATH=/tmp/cogniguard.db

EXPOSE 8765

CMD ["sh", "-c", "uvicorn agent.api_bridge:app --host 0.0.0.0 --port ${PORT:-8765}"]
