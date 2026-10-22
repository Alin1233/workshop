#!/bin/bash
T=172.16.147.10 P=8080 B="http://172.16.147.10:8080"
RUN="/home/alin/Dev/Perso/workshop/attacks/logs/probe-$(date -u +%Y%m%d-%H%M%S)"; mkdir -p "$RUN"; echo "RUN=$RUN"
echo "--- internal/metrics endpoints (expect 404) ---"
for pth in /api/payments/metrics /api/auth/metrics /api/payments/internal/integrity /api/payments/internal /api/auth/.well-known/jwks.json; do
  printf '%-42s %s\n' "$pth" "$(curl -sk -m8 -o /dev/null -w '%{http_code}' "$B$pth")"; sleep 0.2
done
echo "--- admin/integrity + protected without token (expect 401/403) ---"
for pth in /api/payments/admin/integrity /api/payments/accounts/me /api/payments/transfers /api/auth/me; do
  printf '%-42s %s\n' "$pth" "$(curl -sk -m8 -o /dev/null -w '%{http_code}' "$B$pth")"; sleep 0.2
done
echo "--- CORS preflight with evil origin ---"
curl -sk -m8 -D - -o /dev/null -X OPTIONS "$B/api/auth/login" -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: POST' | grep -iE 'access-control|HTTP/' | tee "$RUN/cors.txt"
echo "--- CORS simple GET with Origin ---"
curl -sk -m8 -D - -o /dev/null "$B/api/auth/health" -H 'Origin: https://evil.example' | grep -iE 'access-control|HTTP/'
echo "--- login with invalid creds (check error verbosity) ---"
curl -sk -m8 -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d '{"email":"nobody@test.com","password":"wrongpassword"}' -w '\n[HTTP %{http_code}]\n'
echo "--- login malformed JSON (422 verbosity) ---"
curl -sk -m8 -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d '{"email":123}' -w '\n[HTTP %{http_code}]\n'
echo "--- TRACE method ---"
printf 'TRACE /: %s\n' "$(curl -sk -m8 -o /dev/null -w '%{http_code}' -X TRACE "$B/")"
