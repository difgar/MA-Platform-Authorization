# --- Identidades ------------------------------------------------------------------

# El servicio corre con SU cuenta y no con la de Compute por defecto (la de los nodos de
# GKE, que comparten todos los servicios del cluster): solo conecta a Cloud SQL y lee sus
# secretos.
resource "google_service_account" "auth" {
  account_id   = "ma-authorization"
  display_name = "Servidor de autorizacion (Cloud Run)"
}

resource "google_project_iam_member" "cloudsql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = google_service_account.auth.member

  # Solo ESTA instancia, no todas las de sms-ma-platform (que tambien tiene la MySQL de la
  # plataforma): la condicion acota el permiso aunque el rol se conceda en el proyecto
  # (revision final, 2026-10-03).
  condition {
    title      = "solo-ma-platform-db-pgsql"
    expression = "resource.name == 'projects/sms-ma-platform/instances/ma-platform-db-pgsql' && resource.type == 'sqladmin.googleapis.com/Instance'"
  }
}

# --- Imagenes -----------------------------------------------------------------------

resource "google_artifact_registry_repository" "imagenes" {
  location      = var.region
  repository_id = "ma-authorization"
  format        = "DOCKER"
  description   = "Imagenes del servidor de autorizacion"

  cleanup_policy_dry_run = false
  cleanup_policies {
    id     = "conservar-las-10-ultimas"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }
  cleanup_policies {
    id     = "borrar-las-de-mas-de-90-dias"
    action = "DELETE"
    condition {
      older_than = "7776000s"
    }
  }
}

# Cloud Build con identidad propia (la SA por defecto de Compute tiene roles/editor).
resource "google_service_account" "build" {
  account_id   = "ma-authorization-build"
  display_name = "Cloud Build del servidor de autorizacion"
}

resource "google_storage_bucket" "build" {
  name                        = "${var.project_id}-ma-authorization-build"
  location                    = upper(var.region)
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}

# legacyBucketReader ademas de objectAdmin: Cloud Build lista el bucket de staging y
# objectAdmin no da storage.buckets.get (leccion de MA-Portal).
resource "google_storage_bucket_iam_member" "build" {
  for_each = toset(["roles/storage.objectAdmin", "roles/storage.legacyBucketReader"])

  bucket = google_storage_bucket.build.name
  role   = each.value
  member = google_service_account.build.member
}

resource "google_artifact_registry_repository_iam_member" "build" {
  location   = var.region
  repository = google_artifact_registry_repository.imagenes.name
  role       = "roles/artifactregistry.writer"
  member     = google_service_account.build.member
}

resource "google_project_iam_member" "build_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = google_service_account.build.member
}

# --- Secretos -----------------------------------------------------------------------

# Terraform crea los CONTENEDORES; los valores los carga ../shared/secretos/cargar.sh, para
# que nunca pasen por el state. Los de la base (ma-auth-db-*) los crea
# ../shared/db/crear-base.sh junto con el rol, y aqui solo se leen.
resource "google_secret_manager_secret" "propio" {
  for_each = toset(["ma-auth-google-client-id", "ma-auth-google-client-secret", "ma-auth-jwk"])

  secret_id = each.value
  replication {
    auto {}
  }
}

locals {
  secretos = merge(
    { for k, v in google_secret_manager_secret.propio : k => v.secret_id },
    { "ma-auth-db-user" = "ma-auth-db-user", "ma-auth-db-password" = "ma-auth-db-password" },
  )
}

resource "google_secret_manager_secret_iam_member" "auth" {
  for_each = local.secretos

  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = google_service_account.auth.member
}
