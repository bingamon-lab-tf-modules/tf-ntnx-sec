# tf-ntnx-sec

## Table of Contents

## Overview

A description of the module goes here.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9.0 |
| <a name="requirement_nutanix"></a> [nutanix](#requirement\_nutanix) | >= 2.4.2 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_nutanix"></a> [nutanix](#provider\_nutanix) | 2.4.2 |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [nutanix_category_v2.category](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/resources/category_v2) | resource |
| [nutanix_network_security_policy_v2.policy](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/resources/network_security_policy_v2) | resource |
| [nutanix_categories_v2.existing_categories](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/data-sources/categories_v2) | data source |
| [nutanix_network_security_policies_v2.existing_policies](https://registry.terraform.io/providers/nutanix/nutanix/latest/docs/data-sources/network_security_policies_v2) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_categories"></a> [categories](#input\_categories) | A map of category key/value pairs to manage in Nutanix. Each entry maps to one nutanix\_category\_v2 resource (key + value + optional description). Creating a pair under a pre-existing key needs no special handling. | <pre>map(object({<br/>    key         = string<br/>    value       = string<br/>    description = optional(string, null)<br/>  }))</pre> | `{}` | no |
| <a name="input_network_security_policies"></a> [network\_security\_policies](#input\_network\_security\_policies) | A map of network security policies (v2) to manage in Nutanix Flow. | <pre>map(object({<br/>    name        = string<br/>    description = optional(string, null)<br/>    type        = string                 # QUARANTINE, ISOLATION, APPLICATION<br/>    state       = optional(string, null) # SAVE, MONITOR, ENFORCE<br/><br/>    is_ipv6_traffic_allowed = optional(bool, null)<br/>    is_hitlog_enabled       = optional(bool, null)<br/>    scope                   = optional(string, null)<br/>    vpc_reference           = optional(list(string), [])<br/><br/>    rules = optional(list(object({<br/>      description = optional(string, null)<br/>      type        = string # QUARANTINE, TWO_ENV_ISOLATION, APPLICATION, INTRA_GROUP<br/><br/>      spec = object({<br/>        two_env_isolation_rule_spec = optional(object({<br/>          first_isolation_group  = list(string)<br/>          second_isolation_group = list(string)<br/>        }), null)<br/><br/>        application_rule_spec = optional(object({<br/>          secured_group_category_references = list(string)<br/>          src_allow_spec                    = optional(string, null)<br/>          dest_allow_spec                   = optional(string, null)<br/>          src_category_references           = optional(list(string), [])<br/>          dest_category_references          = optional(list(string), [])<br/>          src_address_group_references      = optional(list(string), [])<br/>          dest_address_group_references     = optional(list(string), [])<br/>          service_group_references          = optional(list(string), [])<br/>          is_all_protocol_allowed           = optional(bool, null)<br/>          network_function_chain_reference  = optional(string, null)<br/><br/>          tcp_services = optional(list(object({<br/>            start_port = number<br/>            end_port   = number<br/>          })), [])<br/><br/>          udp_services = optional(list(object({<br/>            start_port = number<br/>            end_port   = number<br/>          })), [])<br/><br/>          icmp_services = optional(list(object({<br/>            is_all_allowed = optional(bool, null)<br/>            type           = optional(number, null)<br/>            code           = optional(number, null)<br/>          })), [])<br/>        }), null)<br/><br/>        intra_entity_group_rule_spec = optional(object({<br/>          secured_group_action              = string<br/>          secured_group_category_references = list(string)<br/>        }), null)<br/>      })<br/>    })), [])<br/>  }))</pre> | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_categories"></a> [categories](#output\_categories) | Map of created categories (one key/value pair per entry). |
| <a name="output_category_ids"></a> [category\_ids](#output\_category\_ids) | Map of category labels to their external IDs (ext\_id). |
| <a name="output_network_security_policies"></a> [network\_security\_policies](#output\_network\_security\_policies) | Map of created network security policies. |
| <a name="output_network_security_policy_ids"></a> [network\_security\_policy\_ids](#output\_network\_security\_policy\_ids) | Map of network security policy keys to their external IDs. |
| <a name="output_security_summary"></a> [security\_summary](#output\_security\_summary) | Summary of security resources managed by this module. |
<!-- END_TF_DOCS -->
