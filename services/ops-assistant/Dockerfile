# Contexte de build : ./services (pour embarquer le paquet commun)
FROM python:3.12-slim

# CORPUS_ROOT : documents montés en lecture seule par docker-compose. Traçage LangSmith désactivé : aucune donnée ne sort.
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 \
    CORPUS_ROOT=/corpus LANGSMITH_TRACING=false LANGCHAIN_TRACING_V2=false
WORKDIR /app

COPY ops-assistant/requirements.txt .
RUN pip install -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home appuser

COPY common/resilience_common ./resilience_common
COPY ops-assistant/app ./app

USER appuser
EXPOSE 8000
# /health répond 200 tant que le service sert (état d'Ollama et de l'index dans le corps) : un LLM absent ne rend pas
# le conteneur « unhealthy » et ne bloque pas `docker compose up --wait`. Il interroge Ollama et Alertmanager (2 s max chacun).
HEALTHCHECK --interval=15s --timeout=8s --start-period=60s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=7).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--limit-concurrency", "32"]
