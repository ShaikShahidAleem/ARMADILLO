# infrastructure/terraform/modules/shared/vault/main.tf
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  backend         = vault_auth_backend.kubernetes.path
  kubernetes_host = var.kubernetes_host
  kubernetes_ca_cert = var.kubernetes_ca_cert
  token_reviewer_jwt = var.token_reviewer_jwt
}

# Dynamic database credentials
resource "vault_database_secrets_mount" "postgres" {
  path = "database"

  postgresql {
    name                 = "postgres-db"
    connection_url       = "postgresql://{{username}}:{{password}}@${var.db_host}:5432/app?sslmode=require"
    username             = var.db_admin_username
    password             = var.db_admin_password
    max_open_connections = 5
    max_idle_connections = 0
    max_connection_lifetime = "5m"

    verify_connection = true
  }
}

resource "vault_database_secrets_mount" "postgres_role" {
  backend = vault_database_secrets_mount.postgres.path
  name    = "app-role"
  db_name = vault_database_secrets_mount.postgres.postgresql[0].name

  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
  ]

  default_ttl = 3600
  max_ttl     = 86400
}