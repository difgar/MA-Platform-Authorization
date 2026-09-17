package com.mobileamericas.authorization.adapter.token;

import com.mobileamericas.authorization.BaseIT;
import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.RefreshTokenStore;
import com.mobileamericas.authorization.application.port.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    /**
     * OJO con el nombre: esta prueba NO ejercita la rama de la carrera perdida
     * (RefreshTokenStoreJpa.consume(): {@code jpa.marcarUsado(...) == 0}).
     * Poner {@code used_at} ANTES de llamar a consume() hace que la lectura
     * previa ({@code t.usedAt != null}) ya devuelva vacío -el mismo camino,
     * byte a byte, que reutilizar_un_token_ya_consumido_revoca_la_familia_entera-,
     * así que esto prueba la misma rama dos veces con nombres distintos, no la
     * rama que el nombre anterior prometía.
     *
     * La rama real de la carrera perdida (otra transacción concurrente marca
     * usado el token EN EL INTERVALO entre la lectura de este consume() y su
     * propio UPDATE) no tiene hueco de prueba hoy: haría falta una costura
     * (p.ej. poder interceptar entre la lectura y el UPDATE) que no existe, y
     * no se inventa en esta tanda de arreglos. Mejor un nombre honesto y un
     * hueco anotado que una prueba que afirma más de lo que comprueba.
     */
    @Test
    void un_token_ya_marcado_usado_antes_de_consumirlo_se_trata_como_reutilizacion() {
        var emitido = store.issue(userId(), appId());

        // No es la carrera perdida (ver el javadoc de arriba): esto marca
        // 'used_at' ANTES de invocar consume(), así que se detecta en la
        // lectura previa, no en el UPDATE que arbitra la carrera de verdad.
        jdbc.sql("UPDATE auth_refresh_token SET used_at = :ahora WHERE family_id = :fid")
                .param("ahora", Timestamp.from(Instant.now()))
                .param("fid", emitido.familyId().toString())
                .update();

        assertThat(store.consume(emitido.value()))
                .as("un token ya marcado usado se trata como reutilización")
                .isEmpty();

        var revocadas = jdbc.sql("""
                        SELECT count(*) FROM auth_refresh_token
                         WHERE family_id = :fid AND revoked_at IS NOT NULL
                        """)
                .param("fid", emitido.familyId().toString())
                .query(Long.class).single();
        assertThat(revocadas).as("la familia queda revocada").isEqualTo(1L);
    }

    @Test
    void la_rotacion_rechaza_una_familia_ya_revocada() {
        var emitido = store.issue(userId(), appId());
        store.revokeFamily(emitido.familyId());

        assertThatThrownBy(() -> store.rotate(emitido.familyId()))
                .as("la revocación es definitiva para la familia; resultado rutinario, no un bug")
                .isInstanceOf(RefreshTokenStore.RevokedFamilyException.class);
    }

    @Test
    void la_rotacion_de_una_familia_desconocida_es_un_error_distinto_de_la_revocacion() {
        assertThatThrownBy(() -> store.rotate(UUID.randomUUID()))
                .as("una familia que nunca existió es un error interno, no un resultado rutinario")
                .isInstanceOf(RefreshTokenStore.UnknownFamilyException.class);
    }

    @Test
    void un_token_expirado_no_se_consume_aunque_no_este_revocado() {
        var emitido = store.issue(userId(), appId());

        jdbc.sql("UPDATE auth_refresh_token SET expires_at = :pasado WHERE family_id = :fid")
                .param("pasado", Timestamp.from(Instant.now().minusSeconds(60)))
                .param("fid", emitido.familyId().toString())
                .update();

        // La familia no está revocada: si el test pasara igual habiendo
        // invertido o borrado la comparación de expiración, sería porque
        // el cortocircuito lo cuela por la revocación, no por la expiración.
        var revocadas = jdbc.sql("""
                        SELECT count(*) FROM auth_refresh_token
                         WHERE family_id = :fid AND revoked_at IS NOT NULL
                        """)
                .param("fid", emitido.familyId().toString())
                .query(Long.class).single();
        assertThat(revocadas).as("no debe pasar por la rama de revocación").isZero();

        assertThat(store.consume(emitido.value()))
                .as("un token expirado no vale aunque no esté revocado")
                .isEmpty();
    }
}
