# Contexte de build : ./services (pour embarquer le paquet commun)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY auth-service/requirements.txt .
RUN pip install -r requirements.txt \
    && useradd --system --uid 10001 --no-create-home appuser

# Modèles de la reconnaissance faciale (OpenCV Zoo, licences MIT et Apache 2.0) : détection YuNet (230 Ko) et
# empreinte SFace (37 Mo). Téléchargés au build et refusés si leur SHA-256 diffère ; lisibles par appuser, en lecture seule.
ENV FACE_MODELS_DIR=/opt/face-models OPENCV_IO_MAX_IMAGE_PIXELS=4000000
ADD --chmod=644 --checksum=sha256:8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4 \
    https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_detection_yunet/face_detection_yunet_2023mar.onnx \
    /opt/face-models/face_detection_yunet_2023mar.onnx
ADD --chmod=644 --checksum=sha256:0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79 \
    https://media.githubusercontent.com/media/opencv/opencv_zoo/main/models/face_recognition_sface/face_recognition_sface_2021dec.onnx \
    /opt/face-models/face_recognition_sface_2021dec.onnx
# --chmod s'applique aussi au répertoire créé par ADD : sans le droit x, appuser ne pourrait pas y entrer.
RUN chmod 755 /opt/face-models

COPY common/resilience_common ./resilience_common
COPY auth-service/app ./app

USER appuser
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
