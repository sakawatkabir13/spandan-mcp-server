FROM python:3.11-slim AS builder
WORKDIR /build
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes --prefix=/install -r requirements.lock
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps --prefix=/install .

FROM python:3.11-slim
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
    && addgroup --system --gid 10001 spandan && adduser --system --uid 10001 --ingroup spandan spandan
COPY --from=builder /install /usr/local
USER spandan
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8001
HEALTHCHECK --interval=30s --timeout=5s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8001/health/ready', timeout=3)"]
CMD ["uvicorn", "spandan_mcp.server:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8001", "--workers", "2", "--no-access-log"]
