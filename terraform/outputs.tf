output "build_service_account" { value = google_service_account.build.email }
output "build_bucket" { value = google_storage_bucket.build.name }
output "registro" { value = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.imagenes.repository_id}" }
output "backend_service" {
  description = "Lo que referencia el url-map compartido (../shared/urlmap). Null sin imagen."
  value       = one(google_compute_backend_service.auth[*].self_link)
}
