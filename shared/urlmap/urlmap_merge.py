#!/usr/bin/env python3
"""Agrega o reemplaza SOLO las reglas del auth (ma-platform-auth*) en un URL map exportado con gcloud.

Propias = path matchers con nombre que empieza con PREFIX y los host rules que apuntan a ellos.
Todo lo demás se copia sin cambios (se verifica al final). El fragmento trae el conjunto COMPLETO de
reglas propias: las propias que ya estaban se reemplazan, así el comando es idempotente.

Uso:
  urlmap_merge.py --base export.yaml --fragment auth.yaml [--tests tests.yaml] [--reclaim-host HOST ...] --out merged.yaml
  urlmap_merge.py --base export.yaml --remove-own --out merged.yaml
"""
import argparse
import copy
import sys

import yaml

# Copiado de MA-Portal-Infra/shared/urlmap (via MA-TrafficFlow-Infra). Lo del auth empieza
# por este prefijo; lo demas (plataforma, MA-Portal, TrafficFlow) es AJENO y sale identico,
# salvo los hosts que se reclaman a proposito con --reclaim-host.
PREFIX = "ma-platform-auth"


def _own(name):
    return name.startswith(PREFIX)


def _foreign(urlmap):
    hrs = [h for h in urlmap.get("hostRules", []) if not _own(h["pathMatcher"])]
    pms = [p for p in urlmap.get("pathMatchers", []) if not _own(p["name"])]
    return hrs, pms


def _check_foreign_unchanged(before, after):
    if _foreign(before) != _foreign(after):
        raise AssertionError("las reglas ajenas cambiaron")
    for key in before:
        if key not in ("hostRules", "pathMatchers", "tests") and before[key] != after.get(key):
            raise AssertionError(f"cambió el campo ajeno {key}")


def _reclaim(base, hosts):
    """Quita `hosts` de las reglas AJENAS. Una regla que se queda sin hosts se borra, y su
    path matcher tambien si ya no lo usa nadie. Es la UNICA via por la que esta herramienta
    toca algo ajeno, y solo con hosts nombrados explicitamente."""
    if not hosts:
        return base
    out = copy.deepcopy(base)
    soltados = set()
    reglas = []
    for hr in out.get("hostRules", []):
        if not _own(hr["pathMatcher"]) and hosts.intersection(hr["hosts"]):
            hr["hosts"] = [h for h in hr["hosts"] if h not in hosts]
            if not hr["hosts"]:
                soltados.add(hr["pathMatcher"])
                continue
        reglas.append(hr)
    out["hostRules"] = reglas
    en_uso = {hr["pathMatcher"] for hr in reglas}
    out["pathMatchers"] = [pm for pm in out.get("pathMatchers", [])
                           if not (pm["name"] in soltados and pm["name"] not in en_uso)]
    return out


def merge(base, fragment, tests=None, reclaim=frozenset()):
    reclaim = set(reclaim)
    fragment_hosts = {h for hr in fragment.get("hostRules", []) for h in hr["hosts"]}
    for host in reclaim - fragment_hosts:
        raise ValueError(f"se reclama {host} pero no lo usa el fragmento")
    base = _reclaim(base, reclaim)
    names = {pm["name"] for pm in fragment.get("pathMatchers", [])}
    for name in names:
        if not _own(name):
            raise ValueError(f"path matcher sin el prefijo {PREFIX}: {name}")
    foreign_hrs, foreign_pms = _foreign(base)
    foreign_hosts = {h for hr in foreign_hrs for h in hr["hosts"]}
    for hr in fragment.get("hostRules", []):
        if hr["pathMatcher"] not in names:
            raise ValueError(f"host rule apunta a un path matcher que no está en el fragmento: {hr['pathMatcher']}")
        clash = foreign_hosts.intersection(hr["hosts"])
        if clash:
            raise ValueError(f"host ya usado por una regla ajena: {sorted(clash)}")
    out = copy.deepcopy(base)
    out["hostRules"] = foreign_hrs + copy.deepcopy(fragment.get("hostRules", []))
    out["pathMatchers"] = foreign_pms + copy.deepcopy(fragment.get("pathMatchers", []))
    if tests:
        out["tests"] = copy.deepcopy(base.get("tests", [])) + copy.deepcopy(tests)
    _check_foreign_unchanged(base, out)
    return out


def remove_own(base):
    return merge(base, {"hostRules": [], "pathMatchers": []})


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--out", required=True)
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--fragment")
    group.add_argument("--remove-own", action="store_true")
    ap.add_argument("--tests")
    ap.add_argument("--reclaim-host", action="append", default=[],
                    help="host que pasa de una regla ajena al fragmento (explicito, uno por opcion)")
    args = ap.parse_args(argv)
    with open(args.base) as f:
        base = yaml.safe_load(f)
    if args.remove_own:
        out = remove_own(base)
    else:
        with open(args.fragment) as f:
            fragment = yaml.safe_load(f)
        tests = None
        if args.tests:
            with open(args.tests) as f:
                tests = yaml.safe_load(f)["tests"]
        out = merge(base, fragment, tests, reclaim=set(args.reclaim_host))
    with open(args.out, "w") as f:
        yaml.safe_dump(out, f, sort_keys=False)


if __name__ == "__main__":
    main(sys.argv[1:])
