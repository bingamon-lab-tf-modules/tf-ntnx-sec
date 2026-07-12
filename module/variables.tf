##################################################
# Categories (v2)
##################################################

variable "categories" {
  description = "A map of category key/value pairs to manage in Nutanix. Each entry maps to one nutanix_category_v2 resource (key + value + optional description). Creating a pair under a pre-existing key needs no special handling."
  type = map(object({
    key         = string
    value       = string
    description = optional(string, null)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.categories :
      can(regex("^[a-zA-Z0-9._-]+$", v.key)) && can(regex("^[a-zA-Z0-9._-]+$", v.value))
    ])
    error_message = "Category 'key' and 'value' are required, must be non-empty, and may contain only letters, digits, dots, underscores, and hyphens."
  }
}

##################################################
# Network Security Policies (v2 - Flow)
##################################################

variable "network_security_policies" {
  description = "A map of network security policies (v2) to manage in Nutanix Flow."
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

  validation {
    condition = alltrue([
      for k, v in var.network_security_policies :
      contains(["QUARANTINE", "ISOLATION", "APPLICATION"], v.type)
    ])
    error_message = "Network security policy 'type' must be one of: QUARANTINE, ISOLATION, APPLICATION."
  }

  validation {
    condition = alltrue([
      for k, v in var.network_security_policies :
      v.state == null || contains(["SAVE", "MONITOR", "ENFORCE"], v.state)
    ])
    error_message = "Network security policy 'state' must be one of: SAVE, MONITOR, ENFORCE."
  }

  validation {
    condition = alltrue([
      for k, v in var.network_security_policies : alltrue([
        for r in v.rules :
        (r.spec.two_env_isolation_rule_spec != null ? 1 : 0)
        + (r.spec.application_rule_spec != null ? 1 : 0)
        + (r.spec.intra_entity_group_rule_spec != null ? 1 : 0) == 1
      ])
    ])
    error_message = "Each network security policy rule 'spec' must set exactly one of: two_env_isolation_rule_spec, application_rule_spec, intra_entity_group_rule_spec."
  }
}

##################################################
# Data Lookups
##################################################

variable "enable_data_lookups" {
  description = "When true, enables read-only data-source lookups of existing entities (e.g. key management servers). Defaults to false so the module plans cleanly without live Prism Central connectivity."
  type        = bool
  default     = false
}

##################################################
# Key Management Servers (v2)
##################################################

variable "key_management_servers" {
  description = <<-EOT
    A map of external key management servers (KMS) to register for cluster
    data-at-rest encryption (nutanix_key_management_server_v2). Each entry sets a
    name and EXACTLY ONE access-information block: `azure` (Azure Key Vault) or
    `kmip` (a KMIP-compliant vault). This variable carries NON-SECRET config
    only; credential material (client secret, CA/cert PEM, private key) is
    supplied separately via the sensitive `key_management_server_credentials`
    variable, keyed by the same map key.
  EOT
  type = map(object({
    name = string

    azure = optional(object({
      client_id              = string
      tenant_id              = string
      key_id                 = string
      endpoint_url           = string
      credential_expiry_date = string
    }), null)

    kmip = optional(object({
      ca_name = string
      endpoints = list(object({
        port = number
        ipv4 = optional(list(object({
          value         = string
          prefix_length = optional(number, null)
        })), [])
        ipv6 = optional(list(object({
          value         = string
          prefix_length = optional(number, null)
        })), [])
        fqdn = optional(list(object({
          value = string
        })), [])
      }))
    }), null)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.key_management_servers :
      (v.azure != null ? 1 : 0) + (v.kmip != null ? 1 : 0) == 1
    ])
    error_message = "Each key management server must set exactly one access-information block: either 'azure' or 'kmip'."
  }

  validation {
    condition = alltrue([
      for k, v in var.key_management_servers : length(v.name) > 0
    ])
    error_message = "Each key management server must define a non-empty 'name'."
  }
}

variable "key_management_server_credentials" {
  description = <<-EOT
    Sensitive credential material for the key management servers declared in
    `key_management_servers`, keyed by the SAME map key. Azure entries supply
    `client_secret`; KMIP entries supply `ca_pem`, `cert_pem` and `private_key`.
    Feed these from environment-backed TF_VAR_* inputs — never from YAML or
    committed files (spec §10).
  EOT
  type = map(object({
    client_secret = optional(string, null) # Azure Key Vault
    ca_pem        = optional(string, null) # KMIP
    cert_pem      = optional(string, null) # KMIP
    private_key   = optional(string, null) # KMIP
  }))
  default   = {}
  sensitive = true
}
