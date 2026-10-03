package com.mobileamericas.authorization;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lectura minima del terraform del despliegue (terraform/), para los tests que vigilan
 * invariantes de PRODUCCION que antes vivian en kubernetes/deployment.yaml: una sola
 * instancia y el emisor. No es un parser de HCL: busca las pocas formas que esos tests
 * necesitan, y falla si no las encuentra (mejor rojo que un verde que no mira nada).
 */
final class TerraformDelAuth {

    static final Path VARIABLES = Path.of("terraform/variables.tf");
    static final Path SERVICIO = Path.of("terraform/servicio.tf");

    private TerraformDelAuth() {
    }

    /** El {@code default} (cadena) de una variable de variables.tf. */
    static String porDefecto(String variable) throws IOException {
        return grupo(VARIABLES,
                "variable\\s+\"" + Pattern.quote(variable) + "\"\\s*\\{[^}]*?default\\s*=\\s*\"([^\"]*)\"",
                "variable " + variable + " con default");
    }

    /**
     * El valor de un env del contenedor en servicio.tf, tal cual esta escrito: el contenido
     * de la cadena si va entre comillas (con sus ${...}), o la expresion si va suelta
     * (p. ej. {@code var.issuer}).
     */
    static String env(String nombre) throws IOException {
        return grupo(SERVICIO,
                "env\\s*\\{\\s*name\\s*=\\s*\"" + Pattern.quote(nombre) + "\"\\s*value\\s*=\\s*(?:\"([^\"]*)\"|([^\\s\"]+))",
                "env " + nombre);
    }

    /** min_instance_count o max_instance_count del bloque scaling del template. */
    static int escalado(String campo) throws IOException {
        return Integer.parseInt(grupo(SERVICIO,
                "scaling\\s*\\{[^}]*?" + Pattern.quote(campo) + "\\s*=\\s*(\\d+)",
                "scaling." + campo));
    }

    private static String grupo(Path fichero, String regex, String que) throws IOException {
        Matcher m = Pattern.compile(regex, Pattern.DOTALL).matcher(Files.readString(fichero));
        if (!m.find()) {
            throw new AssertionError("no encuentro " + que + " en " + fichero);
        }
        return m.group(1) != null ? m.group(1) : m.group(2);
    }
}
