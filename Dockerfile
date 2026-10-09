FROM python:3.12-slim-trixie@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe AS builder
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements-runtime.lock ./
ARG PIP_DEFAULT_TIMEOUT=180
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels -r requirements-runtime.lock
FROM node:24-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20 AS frontend
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web ./
RUN npm run build
FROM python:3.12-slim-trixie@sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe
ENV APP_ENV=production HF_HUB_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    TMPDIR=/tmp HOME=/tmp OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng tesseract-ocr-hin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 appuser && useradd --uid 10001 --gid 10001 --no-create-home appuser \
    && mkdir -p /var/lib/securesight && chown 10001:10001 /var/lib/securesight
COPY --from=builder /wheels /wheels
COPY requirements-runtime.lock ./
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels -r requirements-runtime.lock \
    && python -m pip check && rm -rf /wheels
COPY app ./app
COPY --from=frontend /app/static/ui ./app/static/ui
COPY utils ./utils
COPY ml ./ml
COPY config ./config
COPY models/v5 ./models/v5
COPY data/blacklist.csv ./data/blacklist.csv
COPY data/metadata ./data/metadata
COPY gunicorn.conf.py ./
RUN python -c "from ml.inference import SecureSightPredictor; p=SecureSightPredictor(); r=p.load(); assert r['status']=='OK', 'Approved model bundle required'"
USER 10001:10001
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/api/v1/health',timeout=3)"
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.app:app"]
