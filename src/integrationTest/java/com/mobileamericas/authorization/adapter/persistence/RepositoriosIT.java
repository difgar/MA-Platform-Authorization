package com.mobileamericas.authorization.adapter.persistence;

import com.mobileamericas.authorization.BaseIT;
import com.mobileamericas.authorization.application.port.AppRepository;
import com.mobileamericas.authorization.application.port.UserRepository;
import com.mobileamericas.authorization.domain.AccessGrant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

public abstract class RepositoriosIT extends BaseIT {

    @Autowired AppRepository apps;
    @Autowired UserRepository usuarios;

    @Test
    void encuentra_la_app_por_su_client_id_de_google() {
        var app = apps.findByGoogleClientId("PENDIENTE-admin");

        assertThat(app).isPresent();
        assertThat(app.get().name()).isEqualTo("admin");
    }

    @Test
    void no_encuentra_un_client_id_desconocido() {
        assertThat(apps.findByGoogleClientId("no-existe")).isEmpty();
    }

    @Test
    void el_catalogo_de_recursos_excluye_los_comodines() {
        var app = apps.findByName("admin").orElseThrow();

        assertThat(apps.resourceCatalogue(app.id()))
                .containsExactlyInAnyOrder("apps", "usuarios", "roles")
                .doesNotContain("*");
    }

    @Test
    void carga_el_usuario_con_sus_roles_y_permisos() {
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();

        assertThat(usuario.roles()).hasSize(2);
        assertThat(usuario.roles()).extracting("name")
                .containsExactlyInAnyOrder("admin", "user");
    }

    @Test
    void el_grant_de_usuario1_en_admin_expande_a_las_doce_autoridades() {
        var app = apps.findByName("admin").orElseThrow();
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();

        var grant = AccessGrant.of(usuario, app, apps.resourceCatalogue(app.id()));

        // 3 recursos x 4 verbos: el rol admin tiene '*:*'
        assertThat(grant.authorities()).hasSize(12)
                .contains("apps:borrar", "usuarios:crear", "roles:editar");
        assertThat(grant.roleNames()).containsExactly("admin");
    }

    @Test
    void el_grant_de_usuario1_en_fgf_solo_tiene_lectura() {
        var fgf = apps.findByName("fgf").orElseThrow();
        var usuario = usuarios.findByEmail("usuario1@pendiente.local").orElseThrow();

        var grant = AccessGrant.of(usuario, fgf, apps.resourceCatalogue(fgf.id()));

        assertThat(grant.authorities()).containsExactly("usuarios:leer");
    }
}
