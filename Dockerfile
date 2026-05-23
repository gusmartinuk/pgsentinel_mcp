FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/tmp

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements.txt ./requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt && pip install argon2-cffi jinja2 bcrypt python-multipart

COPY pyproject.toml ./pyproject.toml
COPY README.md ./README.md
COPY app ./app
COPY config ./config
COPY docs ./docs
COPY tests ./tests
COPY docker/app/entrypoint.sh /entrypoint.sh

RUN mkdir -p /app/audit /secure/pgsentinel /var/log/pgsentinel \
    && chmod +x /entrypoint.sh \
    && chown -R app:app /app /entrypoint.sh /secure/pgsentinel /var/log/pgsentinel

USER app

EXPOSE 8088

ENTRYPOINT ["/entrypoint.sh"]
