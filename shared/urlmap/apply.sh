#!/usr/bin/env bash
# Edita el URL map compartido ma-platform-lb de forma ADITIVA (solo reglas "ma-platform-auth*").
# Los hosts que pasan de una regla ajena a la del auth se nombran con RECLAIM_HOSTS
# (p. ej. RECLAIM_HOSTS=auth.mobile-americas.com); nada mas ajeno se toca.
# Uso:
#   shared/urlmap/apply.sh <fragmento.yaml> [tests.yaml] [--apply]
#   shared/urlmap/apply.sh --remove-own [--apply]
# Sin --apply: exporta, combina, valida y muestra el diff (no cambia nada en GCP).
set -euo pipefail
PROJECT=sms-ma-platform
MAP=ma-platform-lb
DIR="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BK="$DIR/backups"
mkdir -p "$BK"

RECLAIM=(); for h in ${RECLAIM_HOSTS:-}; do RECLAIM+=(--reclaim-host "$h"); done
APPLY=0; ARGS=()
for a in "$@"; do [[ "$a" == "--apply" ]] && APPLY=1 || ARGS+=("$a"); done
# Los argumentos se comprueban ANTES de exportar: con solo --apply exportaba y luego
# moria en "ARGS[0]: unbound variable" (revision final, 2026-10-03).
if [[ ${#ARGS[@]} -eq 0 ]]; then
  echo "uso: [RECLAIM_HOSTS=...] $0 <fragmento.yaml> [tests.yaml] [--apply] | $0 --remove-own [--apply]" >&2; exit 2
fi
if [[ "${ARGS[0]}" != "--remove-own" && ! -f "${ARGS[0]}" ]]; then
  echo "NO: no existe el fragmento ${ARGS[0]}" >&2; exit 2
fi

gcloud compute url-maps export "$MAP" --project="$PROJECT" --global --destination="$BK/$MAP-$TS.yaml" --quiet
if [[ "${ARGS[0]}" == "--remove-own" ]]; then
  python3 "$DIR/urlmap_merge.py" --base "$BK/$MAP-$TS.yaml" --remove-own --out "$BK/merged-$TS.yaml"
  cp "$BK/merged-$TS.yaml" "$BK/validate-$TS.yaml"
else
  python3 "$DIR/urlmap_merge.py" --base "$BK/$MAP-$TS.yaml" --fragment "${ARGS[0]}" ${RECLAIM[@]+"${RECLAIM[@]}"} --out "$BK/merged-$TS.yaml"
  if [[ -n "${ARGS[1]:-}" ]]; then
    python3 "$DIR/urlmap_merge.py" --base "$BK/$MAP-$TS.yaml" --fragment "${ARGS[0]}" ${RECLAIM[@]+"${RECLAIM[@]}"} --tests "${ARGS[1]}" --out "$BK/validate-$TS.yaml"
  else
    cp "$BK/merged-$TS.yaml" "$BK/validate-$TS.yaml"
  fi
fi

result="$(gcloud compute url-maps validate --project="$PROJECT" --global \
  --load-balancing-scheme=EXTERNAL_MANAGED --source="$BK/validate-$TS.yaml" --format=yaml)"
echo "$result"
grep -q "loadSucceeded: true" <<<"$result" || { echo "VALIDACIÓN FALLÓ (load)" >&2; exit 1; }
if grep -q "testPassed" <<<"$result"; then
  grep -q "testPassed: true" <<<"$result" || { echo "VALIDACIÓN FALLÓ (tests)" >&2; exit 1; }
fi

diff -u "$BK/$MAP-$TS.yaml" "$BK/merged-$TS.yaml" || true
if [[ $APPLY -eq 1 ]]; then
  gcloud compute url-maps import "$MAP" --project="$PROJECT" --global --source="$BK/merged-$TS.yaml" --quiet
  echo "IMPORTADO. Respaldo previo: $BK/$MAP-$TS.yaml"
else
  echo "Solo validación. Para aplicar: agregar --apply"
fi
