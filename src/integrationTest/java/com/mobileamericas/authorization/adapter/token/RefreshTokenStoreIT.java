package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.BaseIT;
import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.RefreshTokenStore;
import com.mobileamericas.authorization.application.port.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class RefreshTokenStoreIT extends BaseIT {

    @Autowired RefreshTokenStore store;
    @Autowired AppRepository apps;
    @Autowired UserRepository usuarios;

    private UUID appId() {
        return apps.findByName("admin").orElseThrow().id();
    }

    private UUID userId() {
        return usuarios.findByEmail("usuario1@pendiente.local").orElseThrow().id();
    }

    @Test
    void el_valor_emitido_no_se_guarda_en_claro() {
        var emitido = store.issue(userId(), appId());

        var enBd = jdbc.sql("SELECT count(*) FROM auth_refresh_token WHERE token_hash = :v")
                .param("v", emitido.value()).query(Long.class).single();

        assertThat(enBd).as("el valor en claro no debe estar en la tabla").isZero();
        assertThat(emitido.value()).hasSizeGreaterThan(40);
    }

    @Test
    void un_token_recien_emitido_se_consume_una_vez() {
        var emitido = store.issue(userId(), appId());

        var sujeto = store.consume(emitido.value());

        assertThat(sujeto).isPresent();
        assertThat(sujeto.get().userId()).isEqualTo(userId());
        assertThat(sujeto.get().appId()).isEqualTo(appId());
        assertThat(sujeto.get().familyId()).isEqualTo(emitido.familyId());
    }

    @Test
    void reutilizar_un_token_ya_consumido_revoca_la_familia_entera() {
        var primero = store.issue(userId(), appId());
        store.consume(primero.value());
        var segundo = store.rotate(primero.familyId());

        // Alguien obtuvo una copia del primero y lo reutiliza.
        var reutilizacion = store.consume(primero.value());

        assertThat(reutilizacion).as("un token ya usado no vale").isEmpty();
        assertThat(store.consume(segundo.value()))
                .as("la familia entera queda revocada, incluido el token legítimo")
                .isEmpty();
    }

    @Test
    void un_token_inventado_no_se_consume() {
        assertThat(store.consume("token-que-nadie-emitio")).isEmpty();
    }

    @Test
    void revocar_la_familia_invalida_el_token_vivo() {
        var emitido = store.issue(userId(), appId());

        store.revokeFamily(emitido.familyId());

        assertThat(store.consume(emitido.value())).isEmpty();
    }

    @Test
    void la_rotacion_mantiene_la_familia_y_cambia_el_valor() {
        var primero = store.issue(userId(), appId());
        store.consume(primero.value());

        var segundo = store.rotate(primero.familyId());

        assertThat(segundo.familyId()).isEqualTo(primero.familyId());
        assertThat(segundo.value()).isNotEqualTo(primero.value());
    }

    @Test
    void find_by_id_de_apps_y_usuarios_redondea_el_mismo_registro() {
        var app = apps.findByName("admin").orElseThrow();
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();

        assertThat(apps.findById(app.id())).contains(app);
        assertThat(usuarios.findById(usuario.id())).contains(usuario);
    }
}
