# Contexte de build : ./services (pour embarquer le paquet commun)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY remediation-engine/requirements.txt .
# /state et /waf-blocklist appartiennent à l'utilisateur du service : un volume nommé neuf hérite de ces droits.
RUN pip install -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home appuser \
    && mkdir -p /state /waf-blocklist /bridge \
    && chown 10001:10001 /state /waf-blocklist /bridge

COPY common/resilience_common ./resilience_common
COPY remediation-engine/app ./app

USER appuser
EXPOSE 8000
# /health répond 200 tant que le service sert : pont de restauration, Loki ou proxy indisponibles apparaissent dans
# le corps (« degraded ») sans rendre le conteneur unhealthy ni bloquer `docker compose up --wait`.
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
