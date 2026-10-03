# El servicio y lo que el LB compartido necesita para llegar a el. Se crea cuando hay
# imagen (var.imagen), porque la imagen se construye con el registro ya creado.

locals {
  con_imagen = var.imagen != null ? 1 : 0
}

resource "google_cloud_run_v2_service" "auth" {
  count = local.con_imagen

  name     = "ma-authorization"
  location = var.region

  # Publico SOLO a traves del LB (auth.mobile-americas.com/authorization-api/*).
  ingress              = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  invoker_iam_disabled = true
  deletion_protection  = true

  # El bloque scaling a nivel de servicio lo rellena la API; sin esto cada plan propone
  # quitarlo (visto en TrafficFlow).
  lifecycle {
    ignore_changes = [scaling]
  }

  template {
    service_account                  = google_service_account.auth.email
    execution_environment            = "EXECUTION_ENVIRONMENT_GEN2"
    max_instance_request_concurrency = 80

    scaling {
      # UNA y solo una: el almacen de autorizaciones (codigos en vuelo) vive en memoria
      # (application.yml). Con dos, un codigo emitido por una se canjearia en la otra y
      # fallaria. Es lo que en GKE era replicas: 1 + HPA 1..1 (ReplicaUnicaTest): el MAXIMO
      # es la invariante.
      # Minimo 0 (difgar, 2026-10-03): poco trafico, y asi se evalua. El primer login tras
      # un rato parado espera el arranque (~15-20 s); un login a medias se pierde si la
      # instancia se apaga en ese segundo. Subir a 1 si la espera molesta (~10-15 USD/mes).
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      image = var.imagen

      ports {
        container_port = 8081
      }

      resources {
        limits = { cpu = "1", memory = "1Gi" }
        # CPU solo en peticiones (~10-15 USD/mes): la limpieza de sesiones caducadas puede
        # esperar a la siguiente peticion.
        cpu_idle          = true
        startup_cpu_boost = true
      }

      # Las sondas van al puerto de gestion, como en GKE: el actuator no se publica por 8081.
      startup_probe {
        http_get {
          path = "/actuator/health/readiness"
          port = 18081
        }
        period_seconds    = 5
        timeout_seconds   = 3
        failure_threshold = 36 # 3 min: el primer arranque aplica V1..V7
      }

      liveness_probe {
        http_get {
          path = "/actuator/health/liveness"
          port = 18081
        }
      }

      env {
        name  = "AUTH_ISSUER"
        value = var.issuer
      }
      env {
        name  = "GOOGLE_REDIRECT_URI"
        value = "${var.issuer}/login/oauth2/code/google"
      }
      env {
        name  = "CORS_ALLOWED_ORIGINS"
        value = var.cors_allowed_origins
      }
      env {
        name  = "env"
        value = "production"
      }
      env {
        name  = "SERVER_PORT"
        value = "8081"
      }
      env {
        name  = "MANAGEMENT_SERVER_PORT"
        value = "18081"
      }
      env {
        name  = "JAVA_TOOL_OPTIONS"
        value = "-XX:MaxRAMPercentage=50 -XX:InitialRAMPercentage=25 -Duser.timezone=UTC"
      }
      env {
        name  = "TZ"
        value = "UTC"
      }
      env {
        name  = "JWT_KEY_LOCATIONS"
        value = "file:/etc/ma-auth/keys/active.jwk"
      }
      # cloudSqlRefreshStrategy=lazy: con cpu_idle el conector no puede renovar su
      # certificado en segundo plano, asi que lo renueva al conectar (recomendacion de
      # Google para este modo; revision final, 2026-10-03).
      env {
        name  = "DB_MA_PLATFORM_URL"
        value = "jdbc:postgresql:///ma_auth?cloudSqlInstance=${var.cloudsql_instance}&socketFactory=com.google.cloud.sql.postgres.SocketFactory&cloudSqlRefreshStrategy=lazy"
      }

      dynamic "env" {
        for_each = {
          DB_MA_PLATFORM_USER     = "ma-auth-db-user"
          DB_MA_PLATFORM_PASSWORD = "ma-auth-db-password"
          GOOGLE_CLIENT_ID        = "ma-auth-google-client-id"
          GOOGLE_CLIENT_SECRET    = "ma-auth-google-client-secret"
        }
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value
              version = "latest"
            }
          }
        }
      }

      volume_mounts {
        name       = "jwt-keys"
        mount_path = "/etc/ma-auth/keys"
      }
    }

    volumes {
      name = "jwt-keys"
      secret {
        secret = "ma-auth-jwk"
        items {
          version = "latest"
          path    = "active.jwk"
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_iam_member.auth,
    google_project_iam_member.cloudsql_client,
  ]
}

resource "google_compute_region_network_endpoint_group" "auth" {
  count = local.con_imagen

  name                  = "ma-authorization-neg"
  region                = var.region
  network_endpoint_type = "SERVERLESS"

  cloud_run {
    service = google_cloud_run_v2_service.auth[0].name
  }
}

# Sin Cloud Armor a proposito: una politica que solo permite no protege nada y cuesta
# (difgar quito la equivalente de TrafficFlow el 2026-10-03). Se anade cuando haya una
# regla con sentido, p. ej. un freno a /oauth2/token.
resource "google_compute_backend_service" "auth" {
  count = local.con_imagen

  name                  = "ma-authorization-be"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "HTTPS"

  backend {
    group = google_compute_region_network_endpoint_group.auth[0].id
  }

  log_config {
    enable      = true
    sample_rate = 1.0
  }
}
