##################################################
# Provider Variables
##################################################

variable "nutanix_username" {
  description = "Nutanix Prism Central username"
  type        = string
}

variable "nutanix_password" {
  description = "Nutanix Prism Central password"
  type        = string
  sensitive   = true
}

variable "nutanix_endpoint" {
  description = "Nutanix Prism Central endpoint"
  type        = string
}

variable "nutanix_insecure" {
  description = "Skip TLS verification"
  type        = bool
  default     = false
}

##################################################
# Module Variables
##################################################

variable "category_keys" {
  description = "Map of category keys to create"
  type = map(object({
    name        = string
    description = optional(string, null)
  }))
  default = {}
}

variable "category_values" {
  description = "Map of category values to create. The 'category_key' must reference a key from 'category_keys' or an existing category key name."
  type = map(object({
    category_key = string
    value        = string
    description  = optional(string, null)
  }))
  default = {}
}

variable "network_security_policies" {
  description = "Map of network security policies (v2 - Flow) to create"
  type = map(object({
    name        = string
    description = optional(string, null)
    type        = string                 # QUARANTINE, ISOLATION, APPLICATION
    state       = optional(string, null) # SAVE, MONITOR, ENFORCE

    is_ipv6_traffic_allowed = optional(bool, null)
    is_hitlog_enabled       = optional(bool, null)
    scope                   = optional(string, null)
    vpc_reference           = optional(list(string), [])

    rules = optional(list(object({
      description = optional(string, null)
      type        = string # QUARANTINE, TWO_ENV_ISOLATION, APPLICATION, INTRA_GROUP

      spec = object({
        two_env_isolation_rule_spec = optional(object({
          first_isolation_group  = list(string)
          second_isolation_group = list(string)
        }), null)

        application_rule_spec = optional(object({
          secured_group_category_references = list(string)
          src_allow_spec                    = optional(string, null)
          dest_allow_spec                   = optional(string, null)
          src_category_references           = optional(list(string), [])
          dest_category_references          = optional(list(string), [])
          src_address_group_references      = optional(list(string), [])
          dest_address_group_references     = optional(list(string), [])
          service_group_references          = optional(list(string), [])
          is_all_protocol_allowed           = optional(bool, null)
          network_function_chain_reference  = optional(string, null)

          tcp_services = optional(list(object({
            start_port = number
            end_port   = number
          })), [])

          udp_services = optional(list(object({
            start_port = number
            end_port   = number
          })), [])

          icmp_services = optional(list(object({
            is_all_allowed = optional(bool, null)
            type           = optional(number, null)
            code           = optional(number, null)
          })), [])
        }), null)

        intra_entity_group_rule_spec = optional(object({
          secured_group_action              = string
          secured_group_category_references = list(string)
        }), null)
      })
    })), [])
  }))
  default = {}
}
