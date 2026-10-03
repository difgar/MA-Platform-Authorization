#!/usr/bin/env bash
# Carga los VALORES de los secretos del auth en Secret Manager (sms-ma-platform). Los
# contenedores los crea terraform; los valores no pasan por el state ni se imprimen.
#
#   ma-auth-google-client-id / -secret  <- el client_secret.json del cliente OAuth existente
#   ma-auth-jwk                         <- clave RSA 2048 nueva (GenerarJwk.java)
#
# Idempotente: un secreto que ya tiene version NO se toca. Rotar es otra cosa, a proposito:
#   gcloud secrets versions add <secreto> ... y redesplegar.
#
# Uso: shared/secretos/cargar.sh [ruta/al/client_secret.json]
set -euo pipefail
cd "$(dirname "$0")"
P=sms-ma-platform
JSON="${1:-$HOME/Documents/sms-americas/secretos-locales/ma-platform-admin-client_secret.json}"
KID="prod-$(date -u +%Y-%m)"

tiene_version() { [ -n "$(gcloud secrets versions list "$1" --project=$P --filter='state=ENABLED' --format='value(name)' --limit=1)" ]; }
cargar() {  # cargar <secreto>  (valor por stdin)
    if tiene_version "$1"; then cat >/dev/null; echo "  $1: ya tenia version, no se toca"; return; fi
    gcloud secrets versions add "$1" --project=$P --data-file=- >/dev/null
    echo "  $1: version cargada"
}

[ -f "$JSON" ] || { echo "NO: no encuentro $JSON" >&2; exit 2; }
campo() { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.stdout.write((d.get('web') or d['installed'])[sys.argv[2]])" "$JSON" "$1"; }
campo client_id     | cargar ma-auth-google-client-id
campo client_secret | cargar ma-auth-google-client-secret

NIMBUS="$(find ~/.gradle/caches/modules-2/files-2.1/com.nimbusds/nimbus-jose-jwt/10.9.1 -name 'nimbus-jose-jwt-10.9.1.jar' | head -1)"
[ -n "$NIMBUS" ] || { echo "NO: falta nimbus-jose-jwt 10.9.1 en la cache de gradle (./gradlew build)" >&2; exit 2; }
java -cp "$NIMBUS" GenerarJwk.java "$KID" | cargar ma-auth-jwk

# Comprobacion SIN imprimir valores.
gcloud secrets versions access latest --secret=ma-auth-jwk --project=$P | python3 -c '
import json,sys; k=json.load(sys.stdin)
assert k["kty"]=="RSA" and "d" in k and k["use"]=="sig", "la JWK no es una clave RSA privada de firma"
print("  ma-auth-jwk: RSA privada de firma, kid=" + k["kid"])'
id="$(gcloud secrets versions access latest --secret=ma-auth-google-client-id --project=$P)"
case "$id" in *.apps.googleusercontent.com) echo "  ma-auth-google-client-id: formato correcto";; *) echo "NO: client-id con formato raro" >&2; exit 1;; esac
