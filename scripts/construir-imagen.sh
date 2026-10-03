#!/usr/bin/env bash
# Construye la imagen del auth en Cloud Build y escribe su DIGEST en
# terraform/imagenes.auto.tfvars, que es lo que despliega terraform.
#
# Por digest y no por etiqueta: una etiqueta se puede mover, un digest no, asi que el plan
# de terraform dice exactamente que se va a desplegar. Desde un arbol limpio y commiteado:
# la imagen tiene que corresponder a un commit.
#
# Uso: scripts/construir-imagen.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PROYECTO=sms-ma-platform
REGION=us-east1

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "NO: hay cambios sin commitear" >&2; exit 2
fi

tf() { terraform -chdir=terraform output -raw "$1"; }
sa="$(tf build_service_account)"
bucket="$(tf build_bucket)"
registro="$(tf registro)"

sha="$(git rev-parse --short=12 HEAD)"
img="$registro/ma-authorization:$sha"

gcloud builds submit . --project="$PROYECTO" --region="$REGION" \
    --config=cloudbuild.yaml --substitutions=_IMAGE="$img" \
    --service-account="projects/$PROYECTO/serviceAccounts/$sa" \
    --gcs-source-staging-dir="gs://$bucket/source" \
    --gcs-log-dir="gs://$bucket/logs"

digest="$(gcloud artifacts docker images describe "$img" --format='value(image_summary.digest)')"
[ -n "$digest" ] || { echo "NO: no encuentro el digest de $img" >&2; exit 1; }

printf 'imagen = "%s@%s" # %s\n' "${img%:*}" "$digest" "$sha" > terraform/imagenes.auto.tfvars
echo "imagen = ${img%:*}@$digest  (commit $sha)"
