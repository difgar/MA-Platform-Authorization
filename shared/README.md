# Cambios en recursos compartidos (sms-ma-platform)

La base `ma-platform-db-pgsql` y el LB `ma-platform-lb` los comparten tres proyectos:
**ningún Terraform los gestiona** (decisión de difgar, 2026-10-02). Cada cambio es aditivo,
va a mano y tiene su script aquí. Lo propio del auth (Cloud Run, identidades, secretos,
backend del LB) está en [`../terraform/`](../terraform/).

| Recurso | Script | Qué hace | Cómo se deshace |
|---|---|---|---|
| Base `ma_auth` | `db/crear-base.sh` | Secretos `ma-auth-db-{user,password}`, rol `ma_auth` sin superusuario, base sin CONNECT para PUBLIC | Ver cabecera del script |
| Valores de los secretos | `secretos/cargar.sh` | Cliente OAuth de Google (desde su `client_secret.json`, que vive FUERA del repo, en `~/Documents/sms-americas/secretos-locales/`) y la JWK de firma (RSA 2048, `GenerarJwk.java`). Idempotente: no toca un secreto que ya tiene versión | `gcloud secrets versions destroy` de la versión |

## Medido

- **2026-10-03:** base creada. V1–V7 aplicadas como `ma_auth` dentro de `BEGIN … ROLLBACK`
  contra la instancia real (PostgreSQL 18; los tests corren en 17): 10 tablas, las tres
  apps con su URL, `trafficflow` en `traffic.`. La base quedó vacía: la llena Flyway al
  arrancar el auth.
- **Conexiones:** el auth abre como mucho 3, y aparece como `ma-platform-auth/<revisión>`
  en `pg_stat_activity`. La instancia tiene 50 para todos.
