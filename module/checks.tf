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

# Validate that every configured key management server exposes an endpoint:
# Azure requires an endpoint URL; KMIP requires at least one endpoint, each with
# at least one IPv4/IPv6/FQDN address.
check "key_management_servers_have_endpoint" {
  assert {
    condition = alltrue([
      for k, v in var.key_management_servers :
      v.azure != null ? length(trimspace(v.azure.endpoint_url)) > 0 : (
        length(v.kmip.endpoints) > 0 && alltrue([
          for e in v.kmip.endpoints :
          length(e.ipv4) + length(e.ipv6) + length(e.fqdn) > 0
        ])
      )
    ])
    error_message = "Each key management server must define an endpoint: Azure requires 'endpoint_url'; KMIP requires at least one endpoint carrying an IPv4/IPv6/FQDN address."
  }
}

# Validate that every configured key management server has matching credential
# material supplied via the sensitive key_management_server_credentials map.
check "key_management_server_credentials_present" {
  assert {
    condition = alltrue([
      for k, v in var.key_management_servers :
      v.azure != null ? try(var.key_management_server_credentials[k].client_secret, null) != null : (
        try(var.key_management_server_credentials[k].ca_pem, null) != null &&
        try(var.key_management_server_credentials[k].cert_pem, null) != null &&
        try(var.key_management_server_credentials[k].private_key, null) != null
      )
    ])
    error_message = "Each key management server needs matching credentials in 'key_management_server_credentials' (Azure: client_secret; KMIP: ca_pem, cert_pem, private_key)."
  }
}
