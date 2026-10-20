FROM node:24-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

# Image nginx non privilégiée (écoute sur 8080, utilisateur nginx). Branche stable 1.30 : 1.30.0 est la 1.29.8 figée,
# les versions suivantes n'apportent que des correctifs (le tag 1.29-alpine n'est plus reconstruit depuis mai 2026).
FROM nginxinc/nginx-unprivileged:1.30-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
# Déjà l'utilisateur de l'image (uid 101) : rendu explicite pour les contrôles de configuration (Trivy DS-0002)
USER 101
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
