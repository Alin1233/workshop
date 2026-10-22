#!/bin/bash
T=172.16.147.10 P=8080
RUN="/home/alin/Dev/Perso/workshop/attacks/logs/recon-curl-$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$RUN"; echo "RUNDIR=$RUN"
paths=(/api/auth/docs /api/payments/docs /api/auth/openapi.json /api/payments/openapi.json /api/auth/health /api/payments/health "/api/payments/accounts?id=1" /api/payments/transactions /api/auth/login /nonexistent-xyz)
for path in "${paths[@]}"; do
  code=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "http://$T:$P$path")
  printf '%-42s HTTP %s\n' "$path" "$code"
  sleep 0.3
done
curl -sk -m 8 "http://$T:$P/api/auth/openapi.json" -o "$RUN/auth-openapi.json"
curl -sk -m 8 "http://$T:$P/api/payments/openapi.json" -o "$RUN/pay-openapi.json"
echo "SAVED openapi to $RUN"
