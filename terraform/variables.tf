variable "project_id" {
  type    = string
  default = "sms-ma-platform"

  validation {
    condition     = var.project_id == "sms-ma-platform"
    error_message = "El auth vive en sms-ma-platform. Si de verdad cambia, cambia esta validacion a proposito."
  }
}

variable "region" {
  type    = string
  default = "us-east1"
}

variable "imagen" {
  description = "Imagen del auth fijada por digest; la escribe scripts/construir-imagen.sh en imagenes.auto.tfvars. null = todavia no hay imagen y no se despliega el servicio."
  type        = string
  default     = null
}

variable "issuer" {
  description = "Emisor de los tokens. MS-2 de TrafficFlow y el admin lo fijan igual: cambiarlo invalida todos los tokens."
  type        = string
  default     = "https://auth.mobile-americas.com/authorization-api"
}

variable "cors_allowed_origins" {
  type    = string
  default = "https://admin.mobile-americas.com,https://fgf.mobile-americas.com,https://traffic.mobile-americas.com"
}

variable "cloudsql_instance" {
  description = "Instancia COMPARTIDA: aqui solo se conecta. La base la crea ../shared/db/crear-base.sh."
  type        = string
  default     = "sms-ma-platform:us-east1:ma-platform-db-pgsql"
}
