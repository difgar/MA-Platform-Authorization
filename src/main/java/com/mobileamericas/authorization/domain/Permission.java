package com.mobileamericas.authorization.domain;

import java.util.Objects;

/** Un permiso es un par recurso+verbo. Cualquiera de los dos admite el comodín '*'. */
public record Permission(String resource, String verb) {

    public static final String ANY = "*";

    public Permission {
        Objects.requireNonNull(resource, "resource");
        Objects.requireNonNull(verb, "verb");
        if (resource.isBlank()) {
            throw new IllegalArgumentException("El recurso no puede estar vacío.");
        }
        // Valida el verbo salvo que sea el comodín: 'campanas:escribir' debe fallar
        // aquí y no convertirse en una autoridad que nadie concede nunca.
        if (!ANY.equals(verb)) {
            Verb.of(verb);
        }
    }

    public static Permission parse(String texto) {
        Objects.requireNonNull(texto, "texto");
        int sep = texto.indexOf(':');
        if (sep < 0) {
            throw new IllegalArgumentException(
                    "Un permiso se escribe 'recurso:verbo'. Recibido: '%s'.".formatted(texto));
        }
        return new Permission(texto.substring(0, sep), texto.substring(sep + 1));
    }

    public boolean isWildcard() {
        return ANY.equals(resource) || ANY.equals(verb);
    }

    public String asAuthority() {
        return resource + ":" + verb;
    }
}
