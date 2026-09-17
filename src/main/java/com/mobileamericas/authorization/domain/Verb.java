package com.mobileamericas.authorization.domain;

import java.util.Arrays;
import java.util.Locale;

/**
 * Los cuatro verbos del modelo de permisos.
 *
 * Son cuatro y no dos ("leer"/"escribir") por una razón concreta: el rol
 * support@admin del volcado de producción tiene view, read y update, pero NO
 * create ni delete. Agrupar los tres verbos de escritura le habría concedido un
 * permiso de borrado que hoy no tiene.
 */
public enum Verb {
    CREAR, LEER, EDITAR, BORRAR;

    public String value() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Verb of(String value) {
        return Arrays.stream(values())
                .filter(v -> v.value().equals(value))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "Verbo desconocido: '%s'. Los verbos son: crear, leer, editar, borrar."
                                .formatted(value)));
    }
}
