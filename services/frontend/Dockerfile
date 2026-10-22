FROM node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
# Modèle de détection de visage du guidage de la caméra (MediaPipe BlazeFace, Apache 2.0, 230 Ko), servi par le front
# (copié de public/ par Vite) pour que rien ne parte vers un tiers ; refusé si son SHA-256 diffère.
ADD --chmod=644 --checksum=sha256:b4578f35940bf5a1a655214a1cce5cab13eba73c1297cd78e1a04c2380b0152f \
    https://storage.googleapis.com/mediapipe-models/face_detector/blaze_face_short_range/float16/1/blaze_face_short_range.tflite \
    public/mediapipe/blaze_face_short_range.tflite
RUN chmod 755 public/mediapipe && npm run build

# Image nginx non privilégiée (écoute sur 8080, utilisateur nginx). Branche stable 1.30 : 1.30.0 est la 1.29.8 figée,
# les versions suivantes n'apportent que des correctifs (le tag 1.29-alpine n'est plus reconstruit depuis mai 2026).
FROM nginxinc/nginx-unprivileged:1.30-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
# Déjà l'utilisateur de l'image (uid 101) : rendu explicite pour les contrôles de configuration (Trivy DS-0002)
USER 101
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
