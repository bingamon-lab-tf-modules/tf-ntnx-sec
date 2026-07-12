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
# Address Group Outputs (v2 - Flow)
##################################################

output "address_groups" {
  description = "Map of created address groups (metadata only)."
  value = {
    for k, v in nutanix_address_groups_v2.address_group : k => {
      ext_id      = v.ext_id
      name        = v.name
      description = v.description
    }
  }
}

output "address_group_ids" {
  description = "Map of address group keys to their external IDs (ext_id)."
  value       = { for k, v in nutanix_address_groups_v2.address_group : k => v.ext_id }
}

##################################################
# Service Group Outputs (v2 - Flow)
##################################################

output "service_groups" {
  description = "Map of created service groups (metadata only)."
  value = {
    for k, v in nutanix_service_groups_v2.service_group : k => {
      ext_id      = v.ext_id
      name        = v.name
      description = v.description
    }
  }
}

output "service_group_ids" {
  description = "Map of service group keys to their external IDs (ext_id)."
  value       = { for k, v in nutanix_service_groups_v2.service_group : k => v.ext_id }
}

##################################################
# Entity Group Outputs (v2 - Flow microsegmentation)
##################################################

output "entity_groups" {
  description = "Map of created entity groups (metadata only)."
  value = {
    for k, v in nutanix_entity_group_v2.entity_group : k => {
      ext_id      = v.ext_id
      name        = v.name
      description = v.description
    }
  }
}

output "entity_group_ids" {
  description = "Map of entity group keys to their external IDs (ext_id)."
  value       = { for k, v in nutanix_entity_group_v2.entity_group : k => v.ext_id }
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
# Cluster SSL Certificate Outputs (v2)
##################################################

output "ssl_certificates" {
  description = "Map of managed cluster SSL certificates (metadata only; no private-key material is echoed)."
  value = {
    for k, v in nutanix_ssl_certificate_v2.ssl_certificate : k => {
      ext_id                = v.id
      cluster_ext_id        = v.cluster_ext_id
      private_key_algorithm = v.private_key_algorithm
    }
  }
}

output "ssl_certificate_ids" {
  description = "Map of SSL certificate keys to their external IDs (ext_id)."
  value       = { for k, v in nutanix_ssl_certificate_v2.ssl_certificate : k => v.id }
}

##################################################
# System-Account Password Change Outputs (v2)
##################################################

output "password_change_requests" {
  description = "Map of executed password change requests (request metadata only; no password material is echoed). NOTE: this is a one-shot action — an entry here means a rotation was executed, not that state is continuously enforced."
  value = {
    for k, v in nutanix_password_change_request_v2.password_change_request : k => {
      id     = v.id
      ext_id = v.ext_id
    }
  }
}

output "password_change_request_ids" {
  description = "Map of password change request keys to their request IDs."
  value       = { for k, v in nutanix_password_change_request_v2.password_change_request : k => v.id }
}

##################################################
# Cluster Configuration Profile Outputs (v2)
##################################################

output "cluster_profiles" {
  description = "Map of managed cluster configuration profiles (metadata only)."
  value = {
    for k, v in nutanix_cluster_profile_v2.cluster_profile : k => {
      ext_id = v.ext_id
      name   = v.name
    }
  }
}

output "cluster_profile_ids" {
  description = "Map of cluster profile keys to their external IDs (ext_id)."
  value       = { for k, v in nutanix_cluster_profile_v2.cluster_profile : k => v.ext_id }
}

output "cluster_profile_cluster_associations" {
  description = <<-EOT
    Map of cluster profile key -> resolved cluster ext_ids (association intent).
    The 2.4.2 nutanix_cluster_profile_v2 resource does NOT accept cluster
    associations; consume this in the cluster/PE module to set each cluster's
    cluster_profile_ext_id. Unresolved names are omitted and flagged by the
    cluster_profiles_resolve_clusters check.
  EOT
  value       = local.cluster_profile_cluster_associations
}

##################################################
# Summary
##################################################

output "security_summary" {
  description = "Summary of security resources managed by this module."
  value = {
    total_categories               = length(var.categories)
    total_security_policies        = length(var.network_security_policies)
    isolation_policies             = length(local.isolation_policies)
    application_policies           = length(local.application_policies)
    quarantine_policies            = length(local.quarantine_policies)
    total_address_groups           = length(var.address_groups)
    total_service_groups           = length(var.service_groups)
    total_entity_groups            = length(var.entity_groups)
    total_key_management_servers   = length(var.key_management_servers)
    azure_key_management_servers   = length(local.azure_key_management_servers)
    kmip_key_management_servers    = length(local.kmip_key_management_servers)
    total_ssl_certificates         = length(var.ssl_certificates)
    total_password_change_requests = length(var.password_change_requests)
    total_cluster_profiles         = length(var.cluster_profiles)
  }
}
