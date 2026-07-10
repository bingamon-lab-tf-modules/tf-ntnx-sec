##################################################
# Category Key Outputs
##################################################

output "category_keys" {
  description = "Map of created category keys."
  value = {
    for k, v in nutanix_category_key.key : k => {
      id             = v.id
      name           = v.name
      system_defined = v.system_defined
    }
  }
}

output "category_key_ids" {
  description = "Map of category key labels to their IDs."
  value       = { for k, v in nutanix_category_key.key : k => v.id }
}

##################################################
# Category Value Outputs
##################################################

output "category_values_managed" {
  description = "Map of created category values (managed keys)."
  value = {
    for k, v in nutanix_category_value.value_managed : k => {
      id    = v.id
      name  = v.name
      value = v.value
    }
  }
}

output "category_values_existing" {
  description = "Map of created category values (existing keys)."
  value = {
    for k, v in nutanix_category_value.value_existing : k => {
      id    = v.id
      name  = v.name
      value = v.value
    }
  }
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
# Network Security Rule Outputs (v1)
##################################################

output "network_security_rules" {
  description = "Map of created network security rules (v1)."
  value = {
    for k, v in nutanix_network_security_rule.rule : k => {
      id    = v.id
      name  = v.name
      state = try(v.state, null)
    }
  }
}

output "network_security_rule_ids" {
  description = "Map of network security rule keys to their IDs."
  value       = { for k, v in nutanix_network_security_rule.rule : k => v.id }
}

##################################################
# Summary
##################################################

output "security_summary" {
  description = "Summary of security resources managed by this module."
  value = {
    total_category_keys     = length(var.category_keys)
    total_category_values   = length(var.category_values)
    total_security_policies = length(var.network_security_policies)
    total_security_rules    = length(var.network_security_rules)
    isolation_policies      = length(local.isolation_policies)
    application_policies    = length(local.application_policies)
    quarantine_policies     = length(local.quarantine_policies)
  }
}
