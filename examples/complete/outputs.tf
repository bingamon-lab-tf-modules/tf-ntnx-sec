##################################################
# Outputs
##################################################

output "category_keys" {
  description = "Created category keys"
  value       = module.security.category_keys
}

output "category_key_ids" {
  description = "Category key IDs"
  value       = module.security.category_key_ids
}

output "category_values_managed" {
  description = "Created category values (managed keys)"
  value       = module.security.category_values_managed
}

output "category_values_existing" {
  description = "Created category values (existing keys)"
  value       = module.security.category_values_existing
}

output "network_security_policies" {
  description = "Created network security policies"
  value       = module.security.network_security_policies
}

output "network_security_policy_ids" {
  description = "Network security policy external IDs"
  value       = module.security.network_security_policy_ids
}
