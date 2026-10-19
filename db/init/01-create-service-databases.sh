#!/bin/sh
# Exécuté une seule fois, à la création du volume PostgreSQL.
# Chaque microservice dispose de sa propre base et de son propre rôle (moindre privilège) :
# le service d'auth ne peut pas lire le registre de paiement, et inversement.
set -eu

AUTH_PW="$(cat /run/secrets/auth_db_password)"
PAY_PW="$(cat /run/secrets/pay_db_password)"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v auth_pw="$AUTH_PW" -v pay_pw="$PAY_PW" <<'SQL'
CREATE ROLE auth_svc LOGIN PASSWORD :'auth_pw';
CREATE ROLE pay_svc LOGIN PASSWORD :'pay_pw';
CREATE DATABASE authdb OWNER auth_svc;
CREATE DATABASE paydb OWNER pay_svc;
REVOKE ALL ON DATABASE authdb FROM PUBLIC;
REVOKE ALL ON DATABASE paydb FROM PUBLIC;
SQL
