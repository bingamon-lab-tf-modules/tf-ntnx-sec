##################################################
# Categories (v2)
##################################################

# One nutanix_category_v2 per key/value pair. In the v2 API a category is a
# single (key, value, description) resource; there is no separate key resource
# and no managed-vs-existing-key distinction — creating a pair under a
# pre-existing key uses the exact same resource shape.
resource "nutanix_category_v2" "category" {
  for_each = var.categories

  key         = each.value.key
  value       = each.value.value
  description = each.value.description
}

##################################################
# Network Security Policies (v2)
##################################################

resource "nutanix_network_security_policy_v2" "policy" {
  for_each = var.network_security_policies

  name        = each.value.name
  description = each.value.description
  type        = each.value.type
  state       = each.value.state

  is_ipv6_traffic_allowed = each.value.is_ipv6_traffic_allowed
  is_hitlog_enabled       = each.value.is_hitlog_enabled

  dynamic "rules" {
    for_each = each.value.rules
    content {
      description = rules.value.description
      type        = rules.value.type

      spec {
        dynamic "two_env_isolation_rule_spec" {
          for_each = rules.value.spec.two_env_isolation_rule_spec != null ? [rules.value.spec.two_env_isolation_rule_spec] : []
          content {
            first_isolation_group  = two_env_isolation_rule_spec.value.first_isolation_group
            second_isolation_group = two_env_isolation_rule_spec.value.second_isolation_group
          }
        }

        dynamic "application_rule_spec" {
          for_each = rules.value.spec.application_rule_spec != null ? [rules.value.spec.application_rule_spec] : []
          content {
            secured_group_category_references = application_rule_spec.value.secured_group_category_references
            src_allow_spec                    = application_rule_spec.value.src_allow_spec
            dest_allow_spec                   = application_rule_spec.value.dest_allow_spec
            src_category_references           = length(application_rule_spec.value.src_category_references) > 0 ? application_rule_spec.value.src_category_references : null
            dest_category_references          = length(application_rule_spec.value.dest_category_references) > 0 ? application_rule_spec.value.dest_category_references : null
            src_address_group_references      = length(application_rule_spec.value.src_address_group_references) > 0 ? application_rule_spec.value.src_address_group_references : null
            dest_address_group_references     = length(application_rule_spec.value.dest_address_group_references) > 0 ? application_rule_spec.value.dest_address_group_references : null
            service_group_references          = length(application_rule_spec.value.service_group_references) > 0 ? application_rule_spec.value.service_group_references : null
            is_all_protocol_allowed           = application_rule_spec.value.is_all_protocol_allowed
            network_function_chain_reference  = application_rule_spec.value.network_function_chain_reference

            dynamic "tcp_services" {
              for_each = application_rule_spec.value.tcp_services
              content {
                start_port = tcp_services.value.start_port
                end_port   = tcp_services.value.end_port
              }
            }

            dynamic "udp_services" {
              for_each = application_rule_spec.value.udp_services
              content {
                start_port = udp_services.value.start_port
                end_port   = udp_services.value.end_port
              }
            }

            dynamic "icmp_services" {
              for_each = application_rule_spec.value.icmp_services
              content {
                is_all_allowed = icmp_services.value.is_all_allowed
                type           = icmp_services.value.type
                code           = icmp_services.value.code
              }
            }
          }
        }

        dynamic "intra_entity_group_rule_spec" {
          for_each = rules.value.spec.intra_entity_group_rule_spec != null ? [rules.value.spec.intra_entity_group_rule_spec] : []
          content {
            secured_group_action              = intra_entity_group_rule_spec.value.secured_group_action
            secured_group_category_references = intra_entity_group_rule_spec.value.secured_group_category_references
          }
        }
      }
    }
  }
}

##################################################
# Address Groups (v2 - Flow)
##################################################

# One nutanix_address_groups_v2 per entry: a reusable IP set referenced by
# network security policy application rules. Members are IPv4 addresses (value +
# prefix_length) and/or IP ranges (start_ip/end_ip); at least one is required
# (enforced by var.address_groups validation and the address_groups_have_members
# check).
resource "nutanix_address_groups_v2" "address_group" {
  for_each = var.address_groups

  name        = each.value.name
  description = each.value.description

  dynamic "ipv4_addresses" {
    for_each = each.value.ipv4_addresses
    content {
      value         = ipv4_addresses.value.value
      prefix_length = ipv4_addresses.value.prefix_length
    }
  }

  dynamic "ip_ranges" {
    for_each = each.value.ip_ranges
    content {
      start_ip = ip_ranges.value.start_ip
      end_ip   = ip_ranges.value.end_ip
    }
  }
}

##################################################
# Service Groups (v2 - Flow)
##################################################

# One nutanix_service_groups_v2 per entry: a reusable port/protocol set
# referenced by network security policy application rules. Carries TCP/UDP port
# ranges and/or ICMP services; at least one service is required (enforced by
# var.service_groups validation and the service_groups_have_services check).
resource "nutanix_service_groups_v2" "service_group" {
  for_each = var.service_groups

  name        = each.value.name
  description = each.value.description

  dynamic "tcp_services" {
    for_each = each.value.tcp_services
    content {
      start_port = tcp_services.value.start_port
      end_port   = tcp_services.value.end_port
    }
  }

  dynamic "udp_services" {
    for_each = each.value.udp_services
    content {
      start_port = udp_services.value.start_port
      end_port   = udp_services.value.end_port
    }
  }

  dynamic "icmp_services" {
    for_each = each.value.icmp_services
    content {
      is_all_allowed = icmp_services.value.is_all_allowed
      type           = icmp_services.value.type
      code           = icmp_services.value.code
    }
  }
}

##################################################
# Entity Groups (v2 - Flow microsegmentation)
##################################################

# One nutanix_entity_group_v2 per entry: a microsegmentation policy object that
# selects entities (VMs/subnets/VPCs by category, address groups by ext_id/IP,
# or Kubernetes objects) via an optional allowed_config and/or except_config.
# Each config carries one or more entities; an entity may name references
# (reference_ext_ids/kube_entities) and/or inline IPv4 addresses and ranges. A
# bare name+description (no config) is a valid empty group. except_config
# entities do not accept kube_entities (per the 2.4.2 provider schema).
resource "nutanix_entity_group_v2" "entity_group" {
  for_each = var.entity_groups

  name        = each.value.name
  description = each.value.description

  dynamic "allowed_config" {
    for_each = each.value.allowed_config != null ? [each.value.allowed_config] : []
    content {
      dynamic "entities" {
        for_each = allowed_config.value.entities
        content {
          type              = entities.value.type
          selected_by       = entities.value.selected_by
          reference_ext_ids = length(entities.value.reference_ext_ids) > 0 ? entities.value.reference_ext_ids : null
          kube_entities     = length(entities.value.kube_entities) > 0 ? entities.value.kube_entities : null

          dynamic "addresses" {
            for_each = length(entities.value.ipv4_addresses) > 0 ? [entities.value.ipv4_addresses] : []
            content {
              dynamic "ipv4_addresses" {
                for_each = addresses.value
                content {
                  value         = ipv4_addresses.value.value
                  prefix_length = ipv4_addresses.value.prefix_length
                }
              }
            }
          }

          dynamic "ip_ranges" {
            for_each = length(entities.value.ipv4_ranges) > 0 ? [entities.value.ipv4_ranges] : []
            content {
              dynamic "ipv4_ranges" {
                for_each = ip_ranges.value
                content {
                  start_ip = ipv4_ranges.value.start_ip
                  end_ip   = ipv4_ranges.value.end_ip
                }
              }
            }
          }
        }
      }
    }
  }

  dynamic "except_config" {
    for_each = each.value.except_config != null ? [each.value.except_config] : []
    content {
      dynamic "entities" {
        for_each = except_config.value.entities
        content {
          type              = entities.value.type
          selected_by       = entities.value.selected_by
          reference_ext_ids = length(entities.value.reference_ext_ids) > 0 ? entities.value.reference_ext_ids : null

          dynamic "addresses" {
            for_each = length(entities.value.ipv4_addresses) > 0 ? [entities.value.ipv4_addresses] : []
            content {
              dynamic "ipv4_addresses" {
                for_each = addresses.value
                content {
                  value         = ipv4_addresses.value.value
                  prefix_length = ipv4_addresses.value.prefix_length
                }
              }
            }
          }

          dynamic "ip_ranges" {
            for_each = length(entities.value.ipv4_ranges) > 0 ? [entities.value.ipv4_ranges] : []
            content {
              dynamic "ipv4_ranges" {
                for_each = ip_ranges.value
                content {
                  start_ip = ipv4_ranges.value.start_ip
                  end_ip   = ipv4_ranges.value.end_ip
                }
              }
            }
          }
        }
      }
    }
  }
}

##################################################
# Key Management Servers (v2)
##################################################

# Registers external key management servers used for cluster data-at-rest
# encryption. Each entry carries exactly one access-information block (Azure Key
# Vault or KMIP). Non-secret config comes from var.key_management_servers;
# credential material (client secret, CA/cert PEM, private key) is pulled from
# the sensitive var.key_management_server_credentials, keyed by the same map key.
resource "nutanix_key_management_server_v2" "key_management_server" {
  for_each = var.key_management_servers

  name = each.value.name

  access_information {
    dynamic "azure_key_vault" {
      for_each = each.value.azure != null ? [each.value.azure] : []
      content {
        client_id              = azure_key_vault.value.client_id
        client_secret          = try(var.key_management_server_credentials[each.key].client_secret, null)
        credential_expiry_date = azure_key_vault.value.credential_expiry_date
        endpoint_url           = azure_key_vault.value.endpoint_url
        key_id                 = azure_key_vault.value.key_id
        tenant_id              = azure_key_vault.value.tenant_id
      }
    }

    dynamic "kmip_key_vault" {
      for_each = each.value.kmip != null ? [each.value.kmip] : []
      content {
        ca_name     = kmip_key_vault.value.ca_name
        ca_pem      = try(var.key_management_server_credentials[each.key].ca_pem, null)
        cert_pem    = try(var.key_management_server_credentials[each.key].cert_pem, null)
        private_key = try(var.key_management_server_credentials[each.key].private_key, null)

        dynamic "endpoint_url" {
          for_each = kmip_key_vault.value.endpoints
          content {
            port = endpoint_url.value.port

            ip_address {
              dynamic "fqdn" {
                for_each = endpoint_url.value.fqdn
                content {
                  value = fqdn.value.value
                }
              }
              dynamic "ipv4" {
                for_each = endpoint_url.value.ipv4
                content {
                  value         = ipv4.value.value
                  prefix_length = ipv4.value.prefix_length
                }
              }
              dynamic "ipv6" {
                for_each = endpoint_url.value.ipv6
                content {
                  value         = ipv6.value.value
                  prefix_length = ipv6.value.prefix_length
                }
              }
            }
          }
        }
      }
    }
  }
}

##################################################
# Cluster SSL Certificates (v2)
##################################################

# Installs a managed SSL certificate on each configured cluster. The target
# cluster is named in var.ssl_certificates and resolved to its ext_id via
# nutanix_clusters_v2 (see locals.tf). Only clusters that resolve get a
# resource; unresolved names are caught by the ssl_certificates_resolve_cluster
# check rather than producing a null cluster_ext_id here. Non-secret material
# (public_certificate, ca_chain, private_key_algorithm) comes from
# var.ssl_certificates; the private key and passphrase are pulled from the
# sensitive var.ssl_certificate_keys, keyed by the same map key.
resource "nutanix_ssl_certificate_v2" "ssl_certificate" {
  for_each = local.ssl_certificate_existing

  cluster_ext_id        = local.ssl_certificate_cluster_ext_ids[each.value.cluster_name]
  public_certificate    = each.value.public_certificate
  ca_chain              = each.value.ca_chain
  private_key_algorithm = each.value.private_key_algorithm
  private_key           = try(var.ssl_certificate_keys[each.key].private_key, null)
  passphrase            = try(var.ssl_certificate_keys[each.key].passphrase, null)
}
