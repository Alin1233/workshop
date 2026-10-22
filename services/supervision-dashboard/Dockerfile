# Contexte de build : ./services (pour embarquer le paquet commun resilience_common)
# Étape 1 : construction de l'interface React (Vite + Tailwind) ; les tests (npm test) tournent en CI
FROM node:24-alpine AS web
WORKDIR /web
COPY supervision-dashboard/package.json supervision-dashboard/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY supervision-dashboard/index.html supervision-dashboard/vite.config.ts supervision-dashboard/vitest.config.ts \
     supervision-dashboard/tsconfig.json supervision-dashboard/tsconfig.app.json supervision-dashboard/tsconfig.test.json ./
COPY supervision-dashboard/public ./public
COPY supervision-dashboard/src ./src
RUN npm run build

# Étape 2 : back-for-front Python (FastAPI) qui sert l'interface construite et l'API en lecture seule
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 STATIC_DIR=/app/static
WORKDIR /app

COPY supervision-dashboard/requirements.txt .
RUN pip install -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home appuser

COPY common/resilience_common ./resilience_common
COPY supervision-dashboard/app ./app
COPY --from=web /web/dist ./static

USER appuser
EXPOSE 8000
# /health répond 200 tant que le processus sert, sans interroger aucune source : un moteur, un Loki ou un Prometheus
# arrêté s'affiche dans l'interface (« source indisponible ») sans rendre le conteneur unhealthy (`up --wait`).
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--limit-concurrency", "64"]
