-- El barrido a demanda de postbacks de TrafficFlow: POST /api/v1/admin/postbacks/barrido.
--
-- Desde el 2026-10-03 MS-2 no barre cada 10 s: cada intento fallido programa el siguiente en
-- Cloud Tasks. El barrido a demanda queda para cuando eso falle (una tarea que no se pudo
-- crear salta como alerta) o para forzarlo a mano. Reintenta todo lo vencido con las mismas
-- reglas que el automatismo y NO toca los SIN_CERTEZA (esos solo con reenvios:crear).
--
-- Recurso propio y verbo 'crear' ('barridos:crear'), como 'reenvios:crear' en V5: el verbo es
-- un enum cerrado (crear, leer, editar, borrar) y uno nuevo como 'barrer' se expandiria con el
-- comodin en los tokens de TODAS las aplicaciones. El rol admin de trafficflow (V6, '*:*') lo
-- recibe sin tocarlo.
INSERT INTO auth_permission (id, app_id, resource, verb, description, created_at) VALUES
 ('b0000000-0000-4000-8000-000000000039', 'a0000000-0000-4000-8000-000000000003', 'barridos', 'crear', NULL, TIMESTAMP '2026-10-03 00:00:00');
