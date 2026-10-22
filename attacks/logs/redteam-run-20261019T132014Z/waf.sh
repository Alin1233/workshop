#!/bin/bash
B="http://172.16.147.10:8080"
echo "--- WAF payload tests (expect 403 if WAF blocks) ---"
declare -A t=(
  [sqli_union]="/api/payments/transfers?limit=1%20UNION%20SELECT%20password%20FROM%20users--"
  [sqli_or]="/api/payments/accounts?id=1%27%20OR%20%271%27=%271"
  [xss]="/?q=%3Cscript%3Ealert(1)%3C/script%3E"
  [traversal]="/api/auth/../../../../etc/passwd"
  [cmdinj]="/?x=;cat%20/etc/passwd"
)
for k in "${!t[@]}"; do
  printf '%-14s %s\n' "$k" "$(curl -sk -m8 -o /dev/null -w '%{http_code}' "$B${t[$k]}")"; sleep 0.3
done
echo "--- SQLi in POST body (login email) ---"
curl -sk -m8 -o /dev/null -w 'login_sqli_body: %{http_code}\n' -X POST "$B/api/auth/login" -H 'Content-Type: application/json' -d "{\"email\":\"admin' OR '1'='1\",\"password\":\"x\"}"
