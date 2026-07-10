# Validate that category values reference valid category keys.
check "category_values_reference_valid_keys" {
  assert {
    condition = alltrue([
      for k, v in var.category_values :
      contains(keys(local.managed_category_key_names), v.category_key) || length(v.category_key) > 0
    ])
    error_message = "Category values must reference a managed category key or a valid existing category key name."
  }
}

# Validate that security policies have at least one rule.
check "security_policies_have_rules" {
  assert {
    condition = alltrue([
      for k, v in var.network_security_policies :
      length(v.rules) > 0
    ])
    error_message = "Network security policies should have at least one rule defined."
  }
}
