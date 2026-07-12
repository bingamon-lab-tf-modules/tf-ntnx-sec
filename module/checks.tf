# Validate that every category defines a non-empty key and value.
check "categories_have_key_and_value" {
  assert {
    condition = alltrue([
      for k, v in var.categories :
      length(v.key) > 0 && length(v.value) > 0
    ])
    error_message = "Each category must define a non-empty 'key' and 'value'."
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
