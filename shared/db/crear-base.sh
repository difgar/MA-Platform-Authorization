#!/usr/bin/env bash
# La base del servidor de autorizacion en la instancia COMPARTIDA ma-platform-db-pgsql
# (proyecto sms-ma-platform). La comparten tres proyectos: ningun terraform la gestiona y
# los cambios son ADITIVOS, a mano (spec 2026-10-03-auth-en-cloud-run-design.md).
#
# Que hace, y nada mas:
#   - secretos ma-auth-db-{user,password} en Secret Manager de sms-ma-platform (si no existen)
#   - rol `ma_auth` con login, SIN cloudsqlsuperuser
#   - base `ma_auth`, propiedad de ese rol, sin CONNECT para PUBLIC
# Las tablas las crea Flyway al arrancar el auth (V1..V7), en una base NUEVA Y VACIA: el
# README prohibe baseline-on-migrate.
#
# Requiere el proxy en otra terminal:
#   cloud-sql-proxy sms-ma-platform:us-east1:ma-platform-db-pgsql --port 15441 --gcloud-auth
#
# Deshacer (sin datos de produccion dentro):
#   DROP DATABASE ma_auth; DROP ROLE ma_auth;   -- conectado a postgres
#   gcloud secrets delete ma-auth-db-{user,password} --project=sms-ma-platform
set -euo pipefail
P=sms-ma-platform
PUERTO="${PROXY_PORT:-15441}"
ROL=ma_auth
BASE=ma_auth

secreto() { gcloud secrets versions access latest --secret="$1" --project=$P; }

# --- Secretos: se crean una vez y no se rotan aqui -----------------------------
crear() {  # crear <nombre>  (valor por stdin)
    if gcloud secrets describe "$1" --project=$P >/dev/null 2>&1; then
        cat >/dev/null; return
    fi
    gcloud secrets create "$1" --project=$P --replication-policy=automatic \
        --labels=app=ma-authorization --data-file=-
}
# printf, no echo: un \n final acaba dentro de la contrasena.
printf '%s' "$ROL" | crear ma-auth-db-user
printf '%s' "$(openssl rand -base64 36 | tr -d '/+=\n' | cut -c1-32)" | crear ma-auth-db-password

ADMIN="$(secreto ma-platform-db-pgsql-postgres-user)"
export PGPASSWORD="$(secreto ma-platform-db-pgsql-postgres-password)"
psql_() { psql "host=127.0.0.1 port=$PUERTO dbname=$1 user=$ADMIN sslmode=disable" -v ON_ERROR_STOP=1 -q "${@:2}"; }

# --- Rol y base ----------------------------------------------------------------
# La contrasena entra por variable de entorno (\getenv) y no por linea de comandos: asi
# no se ve en `ps` (hallazgo de la revision final de TrafficFlow).
NUEVA_PW="$(secreto ma-auth-db-password)" psql_ postgres <<SQL
\getenv pw NUEVA_PW
select 'create role $ROL login' where not exists (select from pg_roles where rolname = '$ROL')\gexec
alter role $ROL with login password :'pw';
-- postgres tiene que ser miembro para crear una base cuyo dueno es otro rol (PG16+).
grant $ROL to $ADMIN;
select 'create database $BASE owner $ROL' where not exists (select from pg_database where datname = '$BASE')\gexec
revoke connect, temporary on database $BASE from public;
grant connect, temporary on database $BASE to $ROL;
SQL

# --- Y se comprueba, en vez de fiarse de los CREATE ------------------------------
echo "Comprobacion:"
psql_ postgres -At <<SQL
select 'rol          ' || rolname || ' super=' || rolsuper from pg_roles where rolname = '$ROL';
select 'base         ' || datname || ' dueno=' || pg_get_userbyid(datdba) from pg_database where datname = '$BASE';
select 'public       connect=' || has_database_privilege('public', '$BASE', 'CONNECT');
SQL
PGPASSWORD="$(secreto ma-auth-db-password)" \
    psql "host=127.0.0.1 port=$PUERTO dbname=$BASE user=$ROL sslmode=disable" -At \
    -c "select 'login        ' || current_user || ' en ' || current_database() || ', tablas: ' || count(*) from pg_tables where schemaname = 'public'"
