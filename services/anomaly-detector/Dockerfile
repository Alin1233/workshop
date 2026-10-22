# Contexte de build : ./services (pour embarquer le paquet commun resilience_common)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY anomaly-detector/requirements.txt .
RUN pip install -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home appuser

COPY common/resilience_common ./resilience_common
COPY anomaly-detector/app ./app
# Modèle entraîné versionné avec le service : la démo ne dépend pas d'un ré-entraînement.
COPY anomaly-detector/model ./model

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
