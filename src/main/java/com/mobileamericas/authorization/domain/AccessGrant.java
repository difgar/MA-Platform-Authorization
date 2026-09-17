package com.mobileamericas.authorization.domain;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.TreeSet;

/**
 * Lo que un usuario concreto puede hacer en una app concreta, ya resuelto.
 *
 * Los comodines se expanden AQUÍ y no viajan nunca dentro del token: así el
 * token lleva siempre autoridades concretas y cualquier resource server estándar
 * funciona con hasAuthority() sin una línea de código propio.
 */
public record AccessGrant(User user, App app, Set<String> roleNames, Set<String> authorities) {

    public AccessGrant {
        roleNames = Set.copyOf(roleNames);
        authorities = Set.copyOf(authorities);
    }

    /**
     * @param resourceCatalogue recursos concretos declarados por la app. Si viene
     *                          vacío, un comodín no expande a nada: el grant queda
     *                          vacío en lugar de conceder de más.
     */
    public static AccessGrant of(User user, App app, Set<String> resourceCatalogue) {
        if (!user.active() || !app.active()) {
            return new AccessGrant(user, app, Set.of(), Set.of());
        }

        var rolesDeLaApp = user.roles().stream()
                .filter(rol -> rol.appId().equals(app.id()))
                .toList();

        var nombres = new TreeSet<String>();
        var autoridades = new LinkedHashSet<String>();

        for (var rol : rolesDeLaApp) {
            nombres.add(rol.name());
            for (var permiso : rol.permissions()) {
                autoridades.addAll(expandir(permiso, resourceCatalogue));
            }
        }
        return new AccessGrant(user, app, nombres, new TreeSet<>(autoridades));
    }

    private static Set<String> expandir(Permission permiso, Set<String> catalogo) {
        if (!permiso.isWildcard()) {
            return Set.of(permiso.asAuthority());
        }

        var recursos = Permission.ANY.equals(permiso.resource())
                ? catalogo
                : Set.of(permiso.resource());

        var verbos = Permission.ANY.equals(permiso.verb())
                ? Set.of(Verb.values())
                : Set.of(Verb.of(permiso.verb()));

        var resultado = new LinkedHashSet<String>();
        for (var recurso : recursos) {
            for (var verbo : verbos) {
                resultado.add(recurso + ":" + verbo.value());
            }
        }
        return resultado;
    }

    public boolean isEmpty() {
        return authorities.isEmpty();
    }
}
