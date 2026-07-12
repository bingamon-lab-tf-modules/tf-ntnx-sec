locals {

  ##################################################
  # Network Security Policies
  ##################################################

  # Isolation policies
  isolation_policies = {
    for k, v in var.network_security_policies : k => v if v.type == "ISOLATION"
  }

  # Application policies
  application_policies = {
    for k, v in var.network_security_policies : k => v if v.type == "APPLICATION"
  }

  # Quarantine policies
  quarantine_policies = {
    for k, v in var.network_security_policies : k => v if v.type == "QUARANTINE"
  }

  ##################################################
  # Key Management Servers
  ##################################################

  # Key management servers grouped by access-information type (summary only).
  azure_key_management_servers = {
    for k, v in var.key_management_servers : k => v if v.azure != null
  }

  kmip_key_management_servers = {
    for k, v in var.key_management_servers : k => v if v.kmip != null
  }
}
