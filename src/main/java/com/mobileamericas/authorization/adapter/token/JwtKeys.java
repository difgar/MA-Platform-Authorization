package com.mobileamericas.authorization.adapter.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;

/**
 * El conjunto de claves de firma.
 *
 * Admite varias a la vez para poder rotar sin invalidar nada: se añade la nueva
 * al JWKS, se empieza a firmar con ella, y la vieja se retira cuando expira el
 * último token que firmó (15 minutos). La PRIMERA de la lista es la activa.
 */
public final class JwtKeys {

    private final List<RSAKey> keys;

    private JwtKeys(List<RSAKey> keys) {
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("Hace falta al menos una clave de firma.");
        }
        // Invariantes por clave, exigidas aquí y no en parse(): así valen igual
        // para una clave leída de key-locations que para una construida a mano
        // con forTesting(), en vez de depender de por dónde entró.
        var vistos = new HashSet<String>();
        for (var key : keys) {
            if (!key.isPrivate()) {
                throw new IllegalArgumentException("La clave " + key.getKeyID() + " no tiene parte privada.");
            }
            // El 'kid' es opcional en una JWK, pero aquí no: sin él no hay forma
            // de firmar con una clave concreta de la lista ni de que un
            // consumidor seleccione la correcta al verificar contra el JWKS.
            if (key.getKeyID() == null || key.getKeyID().isBlank()) {
                throw new IllegalArgumentException(
                        "La clave de firma necesita un 'kid'; sin él no se puede seleccionar para firmar ni verificar.");
            }
            // Un kid repetido hace ambigua la selección: ¿con cuál se firmó, o
            // contra cuál debería verificar un consumidor que lee el JWKS?
            if (!vistos.add(key.getKeyID())) {
                throw new IllegalArgumentException(
                        "Hay más de una clave con el kid '" + key.getKeyID() + "'; la selección sería ambigua.");
            }
        }
        this.keys = List.copyOf(keys);
    }

    /** Desde JWK en JSON. La primera es la activa. */
    public static JwtKeys fromJson(List<String> jwksJson) {
        return new JwtKeys(jwksJson.stream().map(JwtKeys::parse).toList());
    }

    public static JwtKeys forTesting(RSAKey... claves) {
        return new JwtKeys(List.of(claves));
    }

    /** Solo convierte JSON en RSAKey; las invariantes viven en el constructor. */
    private static RSAKey parse(String json) {
        try {
            return RSAKey.parse(json);
        } catch (ParseException e) {
            throw new IllegalArgumentException("Clave de firma ilegible.", e);
        }
    }

    public String activeKeyId() {
        return keys.getFirst().getKeyID();
    }

    RSAKey activeKey() {
        return keys.getFirst();
    }

    /** La pública de la clave activa, para validar nuestros propios tokens. */
    public RSAPublicKey activePublicKey() {
        try {
            return activeKey().toRSAPublicKey();
        } catch (JOSEException e) {
            throw new IllegalStateException("La clave activa no expone su parte pública.", e);
        }
    }

    /**
     * El conjunto completo, con parte privada.
     *
     * La fase 1 lo estrechó a package-private y dejó dicho que reabrirlo exigiría
     * un motivo escrito. Este es el motivo: Spring Authorization Server pide un
     * bean JWKSource<SecurityContext> para firmar, y vive en otro paquete.
     *
     * Sigue sin exponerse por ningún endpoint: lo público es publicJwks().
     */
    public JWKSource<SecurityContext> jwkSource() {
        return new ImmutableJWKSet<>(new JWKSet(List.copyOf(keys)));
    }

    /**
     * El conjunto público. {@code toPublicJWKSet()} descarta la parte privada:
     * es lo que impide que 'd', 'p' y 'q' salgan por el endpoint.
     */
    public Map<String, Object> publicJwks() {
        return new JWKSet(List.copyOf(keys)).toPublicJWKSet().toJSONObject();
    }
}
