locals {

  ##################################################
  # Categories
  ##################################################

  # Build a lookup map from category key name to managed resource
  managed_category_key_names = { for k, v in var.category_keys : v.name => k }

  # Category values that reference managed keys
  category_values_with_managed_keys = {
    for k, v in var.category_values : k => v
    if contains(keys(local.managed_category_key_names), v.category_key)
  }

  # Category values that reference existing (unmanaged) keys
  category_values_with_existing_keys = {
    for k, v in var.category_values : k => v
    if !contains(keys(local.managed_category_key_names), v.category_key)
  }

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
  # Network Security Rules (v1)
  ##################################################

  # Isolation rules
  isolation_rules = {
    for k, v in var.network_security_rules : k => v if v.isolation_rule_action != null
  }

  # Application rules
  app_rules = {
    for k, v in var.network_security_rules : k => v if v.app_rule_action != null
  }
}
