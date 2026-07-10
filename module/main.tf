##################################################
# Category Keys
##################################################

resource "nutanix_category_key" "key" {
  for_each = var.category_keys

  name        = each.value.name
  description = each.value.description
}

##################################################
# Category Values (managed keys)
##################################################

resource "nutanix_category_value" "value_managed" {
  for_each = local.category_values_with_managed_keys

  name        = nutanix_category_key.key[local.managed_category_key_names[each.value.category_key]].id
  value       = each.value.value
  description = each.value.description
}

##################################################
# Category Values (existing keys)
##################################################

resource "nutanix_category_value" "value_existing" {
  for_each = local.category_values_with_existing_keys

  name        = each.value.category_key
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
# Network Security Rules (v1 - legacy)
##################################################

resource "nutanix_network_security_rule" "rule" {
  for_each = var.network_security_rules

  name        = each.value.name
  description = each.value.description

  # Isolation Rule
  isolation_rule_action = each.value.isolation_rule_action

  isolation_rule_first_entity_filter_kind_list = length(each.value.isolation_rule_first_entity_filter_kind_list) > 0 ? each.value.isolation_rule_first_entity_filter_kind_list : null
  isolation_rule_first_entity_filter_type      = each.value.isolation_rule_first_entity_filter_type

  dynamic "isolation_rule_first_entity_filter_params" {
    for_each = each.value.isolation_rule_first_entity_filter_params
    content {
      name   = isolation_rule_first_entity_filter_params.value.name
      values = isolation_rule_first_entity_filter_params.value.values
    }
  }

  isolation_rule_second_entity_filter_kind_list = length(each.value.isolation_rule_second_entity_filter_kind_list) > 0 ? each.value.isolation_rule_second_entity_filter_kind_list : null
  isolation_rule_second_entity_filter_type      = each.value.isolation_rule_second_entity_filter_type

  dynamic "isolation_rule_second_entity_filter_params" {
    for_each = each.value.isolation_rule_second_entity_filter_params
    content {
      name   = isolation_rule_second_entity_filter_params.value.name
      values = isolation_rule_second_entity_filter_params.value.values
    }
  }

  # Application Rule
  app_rule_action = each.value.app_rule_action

  app_rule_target_group_default_internal_policy = each.value.app_rule_target_group_default_internal_policy
  app_rule_target_group_peer_specification_type = each.value.app_rule_target_group_peer_specification_type
  app_rule_target_group_filter_kind_list        = length(each.value.app_rule_target_group_filter_kind_list) > 0 ? each.value.app_rule_target_group_filter_kind_list : null
  app_rule_target_group_filter_type             = each.value.app_rule_target_group_filter_type

  dynamic "app_rule_target_group_filter_params" {
    for_each = each.value.app_rule_target_group_filter_params
    content {
      name   = app_rule_target_group_filter_params.value.name
      values = app_rule_target_group_filter_params.value.values
    }
  }

  dynamic "app_rule_inbound_allow_list" {
    for_each = each.value.app_rule_inbound_allow_list
    content {
      peer_specification_type = app_rule_inbound_allow_list.value.peer_specification_type
      ip_subnet               = app_rule_inbound_allow_list.value.ip_subnet
      ip_subnet_prefix_length = app_rule_inbound_allow_list.value.ip_subnet_prefix_length
      protocol                = app_rule_inbound_allow_list.value.protocol
      filter_type             = app_rule_inbound_allow_list.value.filter_type
      filter_kind_list        = length(app_rule_inbound_allow_list.value.filter_kind_list) > 0 ? app_rule_inbound_allow_list.value.filter_kind_list : null

      dynamic "filter_params" {
        for_each = app_rule_inbound_allow_list.value.filter_params
        content {
          name   = filter_params.value.name
          values = filter_params.value.values
        }
      }
    }
  }

  dynamic "app_rule_outbound_allow_list" {
    for_each = each.value.app_rule_outbound_allow_list
    content {
      peer_specification_type = app_rule_outbound_allow_list.value.peer_specification_type
      ip_subnet               = app_rule_outbound_allow_list.value.ip_subnet
      ip_subnet_prefix_length = app_rule_outbound_allow_list.value.ip_subnet_prefix_length
      protocol                = app_rule_outbound_allow_list.value.protocol
      filter_type             = app_rule_outbound_allow_list.value.filter_type
      filter_kind_list        = length(app_rule_outbound_allow_list.value.filter_kind_list) > 0 ? app_rule_outbound_allow_list.value.filter_kind_list : null

      dynamic "filter_params" {
        for_each = app_rule_outbound_allow_list.value.filter_params
        content {
          name   = filter_params.value.name
          values = filter_params.value.values
        }
      }
    }
  }
}
