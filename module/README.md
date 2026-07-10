# tf-ntnx-sec

## Table of Contents

## Overview

A description of the module goes here.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.0 |
| <a name="requirement_nutanix"></a> [nutanix](#requirement\_nutanix) | >= 2.4.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_nutanix"></a> [nutanix](#provider\_nutanix) | 2.4.2 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [nutanix_category_key.key](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/resources/category_key) | resource |
| [nutanix_category_value.value_existing](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/resources/category_value) | resource |
| [nutanix_category_value.value_managed](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/resources/category_value) | resource |
| [nutanix_network_security_policy_v2.policy](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/resources/network_security_policy_v2) | resource |
| [nutanix_network_security_rule.rule](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/resources/network_security_rule) | resource |
| [nutanix_categories_v2.existing_categories](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/data-sources/categories_v2) | data source |
| [nutanix_network_security_policies_v2.existing_policies](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/data-sources/network_security_policies_v2) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_category_keys"></a> [category\_keys](#input\_category\_keys) | A map of category keys to manage in Nutanix. | <pre>map(object({<br/>    name        = string<br/>    description = optional(string, null)<br/>  }))</pre> | `{}` | no |
| <a name="input_category_values"></a> [category\_values](#input\_category\_values) | A map of category values to manage in Nutanix. The 'category\_key' must reference a key from 'category\_keys' or an existing category key name. | <pre>map(object({<br/>    category_key = string<br/>    value        = string<br/>    description  = optional(string, null)<br/>  }))</pre> | `{}` | no |
| <a name="input_network_security_policies"></a> [network\_security\_policies](#input\_network\_security\_policies) | A map of network security policies (v2) to manage in Nutanix Flow. | <pre>map(object({<br/>    name        = string<br/>    description = optional(string, null)<br/>    type        = string                 # QUARANTINE, ISOLATION, APPLICATION<br/>    state       = optional(string, null) # SAVE, MONITOR, ENFORCE<br/><br/>    is_ipv6_traffic_allowed = optional(bool, null)<br/>    is_hitlog_enabled       = optional(bool, null)<br/>    scope                   = optional(string, null)<br/>    vpc_reference           = optional(list(string), [])<br/><br/>    rules = optional(list(object({<br/>      description = optional(string, null)<br/>      type        = string # QUARANTINE, TWO_ENV_ISOLATION, APPLICATION, INTRA_GROUP<br/><br/>      spec = object({<br/>        two_env_isolation_rule_spec = optional(object({<br/>          first_isolation_group  = list(string)<br/>          second_isolation_group = list(string)<br/>        }), null)<br/><br/>        application_rule_spec = optional(object({<br/>          secured_group_category_references = list(string)<br/>          src_allow_spec                    = optional(string, null)<br/>          dest_allow_spec                   = optional(string, null)<br/>          src_category_references           = optional(list(string), [])<br/>          dest_category_references          = optional(list(string), [])<br/>          src_address_group_references      = optional(list(string), [])<br/>          dest_address_group_references     = optional(list(string), [])<br/>          service_group_references          = optional(list(string), [])<br/>          is_all_protocol_allowed           = optional(bool, null)<br/>          network_function_chain_reference  = optional(string, null)<br/><br/>          tcp_services = optional(list(object({<br/>            start_port = number<br/>            end_port   = number<br/>          })), [])<br/><br/>          udp_services = optional(list(object({<br/>            start_port = number<br/>            end_port   = number<br/>          })), [])<br/><br/>          icmp_services = optional(list(object({<br/>            is_all_allowed = optional(bool, null)<br/>            type           = optional(number, null)<br/>            code           = optional(number, null)<br/>          })), [])<br/>        }), null)<br/><br/>        intra_entity_group_rule_spec = optional(object({<br/>          secured_group_action              = string<br/>          secured_group_category_references = list(string)<br/>        }), null)<br/>      })<br/>    })), [])<br/>  }))</pre> | `{}` | no |
| <a name="input_network_security_rules"></a> [network\_security\_rules](#input\_network\_security\_rules) | A map of network security rules (v1) to manage in Nutanix Flow. | <pre>map(object({<br/>    name        = string<br/>    description = optional(string, null)<br/><br/>    # Isolation Rule<br/>    isolation_rule_action = optional(string, null)<br/><br/>    isolation_rule_first_entity_filter_kind_list = optional(list(string), [])<br/>    isolation_rule_first_entity_filter_type      = optional(string, null)<br/>    isolation_rule_first_entity_filter_params = optional(list(object({<br/>      name   = string<br/>      values = list(string)<br/>    })), [])<br/><br/>    isolation_rule_second_entity_filter_kind_list = optional(list(string), [])<br/>    isolation_rule_second_entity_filter_type      = optional(string, null)<br/>    isolation_rule_second_entity_filter_params = optional(list(object({<br/>      name   = string<br/>      values = list(string)<br/>    })), [])<br/><br/>    # Application Rule<br/>    app_rule_action = optional(string, null)<br/><br/>    app_rule_target_group_default_internal_policy = optional(string, null)<br/>    app_rule_target_group_peer_specification_type = optional(string, null)<br/>    app_rule_target_group_filter_kind_list        = optional(list(string), [])<br/>    app_rule_target_group_filter_type             = optional(string, null)<br/>    app_rule_target_group_filter_params = optional(list(object({<br/>      name   = string<br/>      values = list(string)<br/>    })), [])<br/><br/>    app_rule_inbound_allow_list = optional(list(object({<br/>      peer_specification_type = optional(string, null)<br/>      ip_subnet               = optional(string, null)<br/>      ip_subnet_prefix_length = optional(string, null)<br/>      protocol                = optional(string, null)<br/>      filter_type             = optional(string, null)<br/>      filter_kind_list        = optional(list(string), [])<br/>      filter_params = optional(list(object({<br/>        name   = string<br/>        values = list(string)<br/>      })), [])<br/>    })), [])<br/><br/>    app_rule_outbound_allow_list = optional(list(object({<br/>      peer_specification_type = optional(string, null)<br/>      ip_subnet               = optional(string, null)<br/>      ip_subnet_prefix_length = optional(string, null)<br/>      protocol                = optional(string, null)<br/>      filter_type             = optional(string, null)<br/>      filter_kind_list        = optional(list(string), [])<br/>      filter_params = optional(list(object({<br/>        name   = string<br/>        values = list(string)<br/>      })), [])<br/>    })), [])<br/>  }))</pre> | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_category_key_ids"></a> [category\_key\_ids](#output\_category\_key\_ids) | Map of category key labels to their IDs. |
| <a name="output_category_keys"></a> [category\_keys](#output\_category\_keys) | Map of created category keys. |
| <a name="output_category_values_existing"></a> [category\_values\_existing](#output\_category\_values\_existing) | Map of created category values (existing keys). |
| <a name="output_category_values_managed"></a> [category\_values\_managed](#output\_category\_values\_managed) | Map of created category values (managed keys). |
| <a name="output_network_security_policies"></a> [network\_security\_policies](#output\_network\_security\_policies) | Map of created network security policies. |
| <a name="output_network_security_policy_ids"></a> [network\_security\_policy\_ids](#output\_network\_security\_policy\_ids) | Map of network security policy keys to their external IDs. |
| <a name="output_network_security_rule_ids"></a> [network\_security\_rule\_ids](#output\_network\_security\_rule\_ids) | Map of network security rule keys to their IDs. |
| <a name="output_network_security_rules"></a> [network\_security\_rules](#output\_network\_security\_rules) | Map of created network security rules (v1). |
| <a name="output_security_summary"></a> [security\_summary](#output\_security\_summary) | Summary of security resources managed by this module. |
<!-- END_TF_DOCS -->
