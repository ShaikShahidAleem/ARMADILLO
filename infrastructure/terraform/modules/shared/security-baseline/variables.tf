# infrastructure/terraform/modules/shared/security-baseline/variables.tf

variable "cloud_provider" {
  description = "Cloud provider to use (aws, azure, or gcp)"
  type        = string
  validation {
    condition     = contains(["aws", "azure", "gcp"], var.cloud_provider)
    error_message = "Cloud provider must be one of: aws, azure, gcp"
  }
}

variable "network_id" {
  description = "Network/VPC/VNet ID for the cloud provider"
  type        = string
}

variable "enable_network_monitoring" {
  description = "Enable network monitoring (flow logs, network watcher, etc.)"
  type        = bool
  default     = true
}

variable "enable_key_rotation" {
  description = "Enable automatic key rotation for KMS/Key Vault"
  type        = bool
  default     = true
}

variable "enable_audit_logging" {
  description = "Enable audit logging (CloudTrail, Activity Log, etc.)"
  type        = bool
  default     = true
}

# Azure-specific variables
variable "resource_group_name" {
  description = "Azure resource group name (required when cloud_provider is azure)"
  type        = string
  default     = ""
}

variable "key_vault_name" {
  description = "Azure Key Vault name (required when cloud_provider is azure)"
  type        = string
  default     = ""
}

# GCP-specific variables
variable "project_id" {
  description = "GCP project ID (required when cloud_provider is gcp)"
  type        = string
  default     = ""
}
