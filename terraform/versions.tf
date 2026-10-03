# Lo PROPIO del servidor de autorizacion en sms-ma-platform. La base (ma-platform-db-pgsql)
# y el LB (ma-platform-lb) son compartidos por tres proyectos y NO se declaran aqui: sus
# cambios van a mano en ../shared/ (decision de difgar, 2026-10-02).
terraform {
  required_version = ">= 1.9"

  # El bucket se creo a mano una vez (no puede crearlo el terraform que lo usa).
  backend "gcs" {
    bucket = "ma-platform-auth-tfstate"
    prefix = "prod"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region

  default_labels = {
    app        = "ma-authorization"
    managed-by = "terraform"
  }
}
