##################################################
# Category Outputs (v2)
##################################################

output "categories" {
  description = "Map of created categories (one key/value pair per entry)."
  value = {
    for k, v in nutanix_category_v2.category : k => {
      ext_id      = v.id
      key         = v.key
      value       = v.value
      description = v.description
    }
  }
}

output "category_ids" {
  description = "Map of category labels to their external IDs (ext_id)."
  value       = { for k, v in nutanix_category_v2.category : k => v.id }
}

##################################################
# Network Security Policy Outputs (v2)
##################################################

output "network_security_policies" {
  description = "Map of created network security policies."
  value = {
    for k, v in nutanix_network_security_policy_v2.policy : k => {
      ext_id = v.ext_id
      name   = v.name
      type   = v.type
      state  = v.state
    }
  }
}

output "network_security_policy_ids" {
  description = "Map of network security policy keys to their external IDs."
  value       = { for k, v in nutanix_network_security_policy_v2.policy : k => v.ext_id }
}

##################################################
# Key Management Server Outputs (v2)
##################################################

output "key_management_servers" {
  description = "Map of registered key management servers (metadata only; no credential material is echoed)."
  value = {
    for k, v in nutanix_key_management_server_v2.key_management_server : k => {
      ext_id = v.ext_id
      name   = v.name
    }
  }
}

output "key_management_server_ids" {
  description = "Map of key management server keys to their external IDs (ext_id)."
  value       = { for k, v in nutanix_key_management_server_v2.key_management_server : k => v.ext_id }
}

##################################################
# Summary
##################################################

output "security_summary" {
  description = "Summary of security resources managed by this module."
  value = {
    total_categories             = length(var.categories)
    total_security_policies      = length(var.network_security_policies)
    isolation_policies           = length(local.isolation_policies)
    application_policies         = length(local.application_policies)
    quarantine_policies          = length(local.quarantine_policies)
    total_key_management_servers = length(var.key_management_servers)
    azure_key_management_servers = length(local.azure_key_management_servers)
    kmip_key_management_servers  = length(local.kmip_key_management_servers)
  }
}
