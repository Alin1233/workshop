#!/bin/sh
# Resilience-Alpha — garde-fou de la liste de blocage écrite par remediation-engine (volume waf-blocklist).
# Lancé par /docker-entrypoint.sh de l'image juste avant nginx (le fichier doit rester exécutable).
#
# Au rechargement (SIGHUP), un fichier invalide fait seulement échouer le rechargement : nginx garde l'ancienne
# configuration. Au démarrage en revanche, il empêcherait nginx de démarrer et couperait le seul point d'entrée.
# Ce script teste donc la liste seule ; si elle est invalide, il neutralise ses include dans la configuration rendue :
# le WAF démarre sans blocage de remédiation (le CRS reste actif) et le signale par une ligne JSON
# (event_type=waf_blocklist_invalid). Le moteur le voit aussi : sa vérification (port 8081) répond « non bloqué ».
# Un fichier absent est normal (premier démarrage) : rien à faire, l'include en glob l'accepte.
#
# Pas de `set -e` : l'entrypoint de l'image s'arrête au premier script en échec, et ce garde-fou ne doit jamais
# empêcher le démarrage.
set -u

LIST=/waf-blocklist/blocked-ips.conf
CONF=/etc/nginx/conf.d/00-remediation-blocklist.conf

[ -f "$CONF" ] || exit 0
[ -e "$LIST" ] || [ -L "$LIST" ] || exit 0

TEST_DIR=$(mktemp -d 2>/dev/null) || exit 0
cat > "$TEST_DIR/nginx.conf" <<EOF
pid $TEST_DIR/nginx.pid;
events {}
http {
    map \$remote_addr \$remediation_blocked {
        default 0;
        include $LIST;
    }
}
EOF

if err=$(nginx -q -t -e /dev/stderr -c "$TEST_DIR/nginx.conf" 2>&1); then
    rm -rf "$TEST_DIR"
    exit 0
fi
rm -rf "$TEST_DIR"

sed -i 's|^\([[:space:]]*\)include /waf-blocklist/|\1# include neutralisé par 99-remediation-blocklist-guard.sh : /waf-blocklist/|' "$CONF"
detail=$(printf '%s' "$err" | tr -d '"\\' | tr '\n\t' '  ' | cut -c1-300)
printf '{"level":"error","service":"waf","event_type":"waf_blocklist_invalid","file":"%s","detail":"%s"}\n' \
    "$LIST" "$detail"
exit 0
