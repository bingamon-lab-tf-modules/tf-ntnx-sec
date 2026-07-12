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

# Validate that every address group defines at least one member (an IPv4 address
# or an IP range). Mirrors the var.address_groups validation.
check "address_groups_have_members" {
  assert {
    condition = alltrue([
      for k, v in var.address_groups :
      length(v.ipv4_addresses) + length(v.ip_ranges) > 0
    ])
    error_message = "Each address group must define at least one 'ipv4_addresses' entry or one 'ip_ranges' entry."
  }
}

# Validate that every service group defines at least one service (TCP, UDP or
# ICMP). Mirrors the var.service_groups validation.
check "service_groups_have_services" {
  assert {
    condition = alltrue([
      for k, v in var.service_groups :
      length(v.tcp_services) + length(v.udp_services) + length(v.icmp_services) > 0
    ])
    error_message = "Each service group must define at least one 'tcp_services', 'udp_services', or 'icmp_services' entry."
  }
}

# Validate that every entity group entity uses a documented (selected_by, type)
# pair. Mirrors the var.entity_groups validation; an unsupported combination is
# rejected by Nutanix Flow, so surface it here with a clear message.
check "entity_groups_valid_selection" {
  assert {
    condition = alltrue([
      for k, v in var.entity_groups : alltrue(concat(
        [for e in(v.allowed_config != null ? v.allowed_config.entities : []) :
        e.type == null || e.selected_by == null || contains(["CATEGORY_EXT_ID:VM", "CATEGORY_EXT_ID:SUBNET", "CATEGORY_EXT_ID:VPC", "EXT_ID:KUBE_CLUSTER", "EXT_ID:ADDRESS_GROUP", "LABELS:KUBE_PODS", "NAME:KUBE_NAMESPACE", "NAME:KUBE_SERVICE", "IP_VALUES:ADDRESS_GROUP"], "${coalesce(e.selected_by, "_")}:${coalesce(e.type, "_")}")],
        [for e in(v.except_config != null ? v.except_config.entities : []) :
        e.type == null || e.selected_by == null || contains(["CATEGORY_EXT_ID:VM", "CATEGORY_EXT_ID:SUBNET", "CATEGORY_EXT_ID:VPC", "EXT_ID:KUBE_CLUSTER", "EXT_ID:ADDRESS_GROUP", "LABELS:KUBE_PODS", "NAME:KUBE_NAMESPACE", "NAME:KUBE_SERVICE", "IP_VALUES:ADDRESS_GROUP"], "${coalesce(e.selected_by, "_")}:${coalesce(e.type, "_")}")]
      ))
    ])
    error_message = "Each entity group entity must use a valid (selected_by, type) pair per Nutanix Flow microsegmentation."
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

# Validate that every configured SSL certificate names a cluster that resolves
# to an ext_id via nutanix_clusters_v2. An unknown cluster name surfaces here
# with a clear message instead of producing a null cluster_ext_id downstream.
check "ssl_certificates_resolve_cluster" {
  assert {
    condition     = length(local.ssl_certificate_missing_clusters) == 0
    error_message = "The following SSL certificate 'cluster_name' values did not resolve to a cluster in Nutanix: ${jsonencode(local.ssl_certificate_missing_clusters)}. Ensure each name matches an existing cluster."
  }
}

# Validate that every configured SSL certificate has matching private-key
# material supplied via the sensitive ssl_certificate_keys map.
check "ssl_certificate_keys_present" {
  assert {
    condition = alltrue([
      for k, v in var.ssl_certificates :
      try(var.ssl_certificate_keys[k].private_key, null) != null
    ])
    error_message = "Each SSL certificate needs a 'private_key' in the sensitive 'ssl_certificate_keys' map, keyed by the same map key."
  }
}

# Validate that every configured password change request has a matching
# new_password in the sensitive password_change_secrets map, keyed identically.
# new_password is a required provider attribute, so a missing secret is caught
# here with a clear message rather than a raw required-argument error (the
# request is also excluded from the managed resource; see locals.tf).
check "password_change_secrets_present" {
  assert {
    condition = alltrue([
      for k, v in var.password_change_requests :
      try(var.password_change_secrets[k].new_password, null) != null
    ])
    error_message = "Each password change request needs a 'new_password' in the sensitive 'password_change_secrets' map, keyed by the same map key. Trigger a rotation by adding/renaming a matching entry in both maps."
  }
}
