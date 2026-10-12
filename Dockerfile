FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN pip install --upgrade pip && \
    pip install -r /app/requirements.txt && \
    chmod +x /usr/local/bin/docker-entrypoint.sh

COPY . /app

ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 8000
