# infrastructure/terraform/modules/shared/security-baseline/main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

# Multi-cloud security baseline
module "aws_security" {
  count  = var.cloud_provider == "aws" ? 1 : 0
  source = "../aws/security"

  vpc_id                = var.network_id
  enable_flow_logs     = var.enable_network_monitoring
  kms_key_rotation     = var.enable_key_rotation
  cloudtrail_enabled   = var.enable_audit_logging
}

module "azure_security" {
  count  = var.cloud_provider == "azure" ? 1 : 0
  source = "../azure/security"

  resource_group_name     = var.resource_group_name
  vnet_id                = var.network_id
  enable_network_watcher = var.enable_network_monitoring
  key_vault_name         = var.key_vault_name
}

module "gcp_security" {
  count  = var.cloud_provider == "gcp" ? 1 : 0
  source = "../gcp/security"

  project_id              = var.project_id
  vpc_network            = var.network_id
  enable_vpc_flow_logs   = var.enable_network_monitoring
  enable_audit_logs      = var.enable_audit_logging
}