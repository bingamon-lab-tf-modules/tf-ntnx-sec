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
# Address Groups (v2 - Flow)
##################################################

variable "address_groups" {
  description = <<-EOT
    A map of Flow address groups (reusable IP sets) to manage
    (nutanix_address_groups_v2). Each entry sets a name and at least one member:
    an `ipv4_addresses` entry (a value + prefix_length, e.g. 10.0.10.0/24) or an
    `ip_ranges` entry (start_ip/end_ip). Address groups are referenced by
    network security policy application rules via their ext_id
    (`src_address_group_references` / `dest_address_group_references`).
  EOT
  type = map(object({
    name        = string
    description = optional(string, null)
    ipv4_addresses = optional(list(object({
      value         = string
      prefix_length = number
    })), [])
    ip_ranges = optional(list(object({
      start_ip = string
      end_ip   = string
    })), [])
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.address_groups : length(trimspace(v.name)) > 0
    ])
    error_message = "Each address group must define a non-empty 'name'."
  }

  validation {
    condition = alltrue([
      for k, v in var.address_groups :
      length(v.ipv4_addresses) + length(v.ip_ranges) > 0
    ])
    error_message = "Each address group must define at least one 'ipv4_addresses' entry or one 'ip_ranges' entry."
  }

  validation {
    condition = alltrue([
      for k, v in var.address_groups : alltrue([
        for a in v.ipv4_addresses : a.prefix_length >= 0 && a.prefix_length <= 32
      ])
    ])
    error_message = "Each address group 'ipv4_addresses' entry must set a 'prefix_length' between 0 and 32."
  }
}

##################################################
# Service Groups (v2 - Flow)
##################################################

variable "service_groups" {
  description = <<-EOT
    A map of Flow service groups (reusable port/protocol sets) to manage
    (nutanix_service_groups_v2). Each entry sets a name and at least one service:
    `tcp_services` / `udp_services` (start_port/end_port ranges) or
    `icmp_services` (type/code, or is_all_allowed). Service groups are referenced
    by network security policy application rules via their ext_id
    (`service_group_references`).
  EOT
  type = map(object({
    name        = string
    description = optional(string, null)
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
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.service_groups : length(trimspace(v.name)) > 0
    ])
    error_message = "Each service group must define a non-empty 'name'."
  }

  validation {
    condition = alltrue([
      for k, v in var.service_groups :
      length(v.tcp_services) + length(v.udp_services) + length(v.icmp_services) > 0
    ])
    error_message = "Each service group must define at least one 'tcp_services', 'udp_services', or 'icmp_services' entry."
  }

  validation {
    condition = alltrue([
      for k, v in var.service_groups : alltrue([
        for s in concat(v.tcp_services, v.udp_services) :
        s.start_port >= 1 && s.start_port <= 65535 &&
        s.end_port >= 1 && s.end_port <= 65535 &&
        s.start_port <= s.end_port
      ])
    ])
    error_message = "Each service group TCP/UDP service port must be between 1 and 65535, with 'start_port' <= 'end_port'."
  }
}

##################################################
# Entity Groups (v2 - Flow microsegmentation)
##################################################

variable "entity_groups" {
  description = <<-EOT
    A map of Flow entity groups (microsegmentation policy objects) to manage
    (nutanix_entity_group_v2). Each entry sets a name and, optionally, an
    `allowed_config` and/or `except_config` describing which entities the group
    selects. Each config holds one or more `entities` blocks; an entity pairs a
    `type` (VM, SUBNET, VPC, ADDRESS_GROUP, KUBE_NAMESPACE, KUBE_SERVICE,
    KUBE_CLUSTER, KUBE_PODS) with a `selected_by` method (CATEGORY_EXT_ID,
    EXT_ID, IP_VALUES, LABELS, NAME) and the matching members:
    `reference_ext_ids` (category/subnet/vpc/address-group ext_ids),
    `kube_entities` (Kubernetes identifiers, allowed_config only), or inline
    `ipv4_addresses` (value + prefix_length) / `ipv4_ranges` (start_ip/end_ip).
    A bare name + description (no config) is valid. Entity groups are referenced
    as sources/targets by network security policies.
  EOT
  type = map(object({
    name        = string
    description = optional(string, null)
    allowed_config = optional(object({
      entities = list(object({
        type              = optional(string, null)
        selected_by       = optional(string, null)
        reference_ext_ids = optional(list(string), [])
        kube_entities     = optional(list(string), [])
        ipv4_addresses = optional(list(object({
          value         = string
          prefix_length = optional(number, null)
        })), [])
        ipv4_ranges = optional(list(object({
          start_ip = string
          end_ip   = string
        })), [])
      }))
    }), null)
    except_config = optional(object({
      entities = list(object({
        type              = optional(string, null)
        selected_by       = optional(string, null)
        reference_ext_ids = optional(list(string), [])
        ipv4_addresses = optional(list(object({
          value         = string
          prefix_length = optional(number, null)
        })), [])
        ipv4_ranges = optional(list(object({
          start_ip = string
          end_ip   = string
        })), [])
      }))
    }), null)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.entity_groups : length(trimspace(v.name)) > 0
    ])
    error_message = "Each entity group must define a non-empty 'name'."
  }

  validation {
    condition = alltrue([
      for k, v in var.entity_groups :
      v.allowed_config == null ? true : alltrue([
        for e in v.allowed_config.entities :
        e.type == null || contains(["VM", "SUBNET", "VPC", "ADDRESS_GROUP", "KUBE_NAMESPACE", "KUBE_SERVICE", "KUBE_CLUSTER", "KUBE_PODS"], coalesce(e.type, "_"))
      ])
    ])
    error_message = "Each allowed_config entity 'type' must be one of: VM, SUBNET, VPC, ADDRESS_GROUP, KUBE_NAMESPACE, KUBE_SERVICE, KUBE_CLUSTER, KUBE_PODS."
  }

  validation {
    condition = alltrue([
      for k, v in var.entity_groups :
      v.allowed_config == null ? true : alltrue([
        for e in v.allowed_config.entities :
        e.selected_by == null || contains(["IP_VALUES", "EXT_ID", "CATEGORY_EXT_ID", "LABELS", "NAME"], coalesce(e.selected_by, "_"))
      ])
    ])
    error_message = "Each allowed_config entity 'selected_by' must be one of: IP_VALUES, EXT_ID, CATEGORY_EXT_ID, LABELS, NAME."
  }

  # except_config is deliberately narrow in the 2.4.2 provider: it only excludes
  # address groups selected by ext_id or literal IP values.
  validation {
    condition = alltrue([
      for k, v in var.entity_groups :
      v.except_config == null ? true : alltrue([
        for e in v.except_config.entities :
        (e.type == null || coalesce(e.type, "_") == "ADDRESS_GROUP") &&
        (e.selected_by == null || contains(["EXT_ID", "IP_VALUES"], coalesce(e.selected_by, "_")))
      ])
    ])
    error_message = "Each except_config entity must set 'type' = ADDRESS_GROUP and 'selected_by' one of: EXT_ID, IP_VALUES."
  }

  validation {
    condition = alltrue([
      for k, v in var.entity_groups : alltrue(concat(
        [for e in(v.allowed_config != null ? v.allowed_config.entities : []) :
        e.type == null || e.selected_by == null || contains(["CATEGORY_EXT_ID:VM", "CATEGORY_EXT_ID:SUBNET", "CATEGORY_EXT_ID:VPC", "EXT_ID:KUBE_CLUSTER", "EXT_ID:ADDRESS_GROUP", "LABELS:KUBE_PODS", "NAME:KUBE_NAMESPACE", "NAME:KUBE_SERVICE", "IP_VALUES:ADDRESS_GROUP"], "${coalesce(e.selected_by, "_")}:${coalesce(e.type, "_")}")],
        [for e in(v.except_config != null ? v.except_config.entities : []) :
        e.type == null || e.selected_by == null || contains(["CATEGORY_EXT_ID:VM", "CATEGORY_EXT_ID:SUBNET", "CATEGORY_EXT_ID:VPC", "EXT_ID:KUBE_CLUSTER", "EXT_ID:ADDRESS_GROUP", "LABELS:KUBE_PODS", "NAME:KUBE_NAMESPACE", "NAME:KUBE_SERVICE", "IP_VALUES:ADDRESS_GROUP"], "${coalesce(e.selected_by, "_")}:${coalesce(e.type, "_")}")]
      ))
    ])
    error_message = "Each entity must use a valid (selected_by, type) pair: (CATEGORY_EXT_ID, VM/SUBNET/VPC), (EXT_ID, KUBE_CLUSTER/ADDRESS_GROUP), (LABELS, KUBE_PODS), (NAME, KUBE_NAMESPACE/KUBE_SERVICE), (IP_VALUES, ADDRESS_GROUP)."
  }

  validation {
    condition = alltrue([
      for k, v in var.entity_groups : alltrue(concat(
        [for e in(v.allowed_config != null ? v.allowed_config.entities : []) : alltrue([
          for a in e.ipv4_addresses : a.prefix_length == null || (coalesce(a.prefix_length, 0) >= 0 && coalesce(a.prefix_length, 0) <= 32)
        ])],
        [for e in(v.except_config != null ? v.except_config.entities : []) : alltrue([
          for a in e.ipv4_addresses : a.prefix_length == null || (coalesce(a.prefix_length, 0) >= 0 && coalesce(a.prefix_length, 0) <= 32)
        ])]
      ))
    ])
    error_message = "Each entity 'ipv4_addresses' entry 'prefix_length' must be between 0 and 32."
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

##################################################
# Cluster SSL Certificates (v2)
##################################################

variable "ssl_certificates" {
  description = <<-EOT
    A map of cluster SSL certificates to manage (nutanix_ssl_certificate_v2),
    keyed by cluster. Each entry names the target cluster (`cluster_name`),
    which is resolved to its ext_id at plan time via nutanix_clusters_v2, and
    carries the NON-SECRET certificate material: the PEM-encoded public
    certificate, an optional CA chain, and the private-key algorithm. The
    private key itself and any passphrase are SECRET and supplied separately via
    the sensitive `ssl_certificate_keys` variable, keyed by the same map key
    (spec §10). NEVER put private-key material in this variable.
  EOT
  type = map(object({
    cluster_name          = string
    public_certificate    = optional(string, null)
    ca_chain              = optional(string, null)
    private_key_algorithm = optional(string, null)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.ssl_certificates : length(trimspace(v.cluster_name)) > 0
    ])
    error_message = "Each SSL certificate entry must set a non-empty 'cluster_name'."
  }
}

variable "ssl_certificate_keys" {
  description = <<-EOT
    Sensitive private-key material for the cluster SSL certificates declared in
    `ssl_certificates`, keyed by the SAME map key. Supply `private_key` (the
    PEM-encoded private key) and an optional `passphrase`. Feed these from
    environment-backed TF_VAR_* inputs — never from YAML or committed files
    (spec §10).
  EOT
  type = map(object({
    private_key = optional(string, null)
    passphrase  = optional(string, null)
  }))
  default   = {}
  sensitive = true
}

##################################################
# System-Account Password Changes (v2)
##################################################

variable "password_change_requests" {
  description = <<-EOT
    A map of system-account password changes to execute
    (nutanix_password_change_request_v2), keyed by an operator-chosen rotation
    trigger. Each entry names WHICH account to rotate via `ext_id` (the system
    user's external ID); it carries NO password material. The new password (and
    optional current password) are supplied separately via the sensitive
    `password_change_secrets` variable, keyed by the SAME map key (spec §10) —
    passwords can never be expressed here.

    ONE-SHOT ACTION, NOT DECLARATIVE STATE: creating an entry executes the
    password change exactly once — it does NOT continuously enforce the password.
    Re-running a rotation requires a changed for_each key or attribute (or a
    manual taint): operators trigger a new rotation by ADDING or RENAMING a map
    entry (e.g. `rotate_2026_q3_admin`). Destroying an entry does NOT restore the
    old password.
  EOT
  type = map(object({
    ext_id = string
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.password_change_requests : length(trimspace(v.ext_id)) > 0
    ])
    error_message = "Each password change request must set a non-empty 'ext_id' identifying the system user account to rotate."
  }
}

variable "password_change_secrets" {
  description = <<-EOT
    Sensitive password material for the system-account rotations declared in
    `password_change_requests`, keyed by the SAME map key. Supply `new_password`
    (required — the new password to set) and optionally `current_password` (the
    existing password, where the account requires it to authorize the change).
    Feed these from environment-backed TF_VAR_* inputs — never from YAML or
    committed files (spec §10).

    A rotation runs exactly once per distinct map key; add or rename a key (in
    both this map and `password_change_requests`) to trigger another rotation.
  EOT
  type = map(object({
    new_password     = string
    current_password = optional(string, null)
  }))
  default   = {}
  sensitive = true
}

##################################################
# Cluster Configuration Profiles (v2)
##################################################

variable "cluster_profiles" {
  description = <<-EOT
    A map of cluster configuration profiles to manage
    (nutanix_cluster_profile_v2) — governance-grade drift control for
    cluster-level settings (DNS/name servers, NTP, remote syslog, Pulse
    telemetry, allowed overrides, NFS subnet whitelist). Each entry sets a
    `name` and the non-secret setting blocks it governs.

    ASSOCIATION INTENT (`clusters`): the 2.4.2 nutanix_cluster_profile_v2
    resource has NO input to associate/apply the profile to clusters — its
    `clusters` attribute is read-only. The cluster→profile association is set
    CLUSTER-SIDE (via each cluster's `cluster_profile_ext_id`). This module
    therefore treats the per-profile `clusters` list (cluster NAMES) as
    association INTENT: it resolves the names to ext_ids at plan time and
    surfaces them via the `cluster_profile_cluster_associations` output for the
    cluster/PE module to consume. Unknown names are caught by the
    `cluster_profiles_resolve_clusters` check.

    SECRET-BEARING BLOCKS DEFERRED: the provider's `smtp_server` and
    `snmp_config` blocks carry credential material (SMTP password, SNMP
    auth/priv keys, trap community string). Per the module's secret-handling
    convention (spec §10 — secrets flow through separate sensitive vars, never
    YAML), those two blocks are intentionally not modelled here and are left to
    a follow-up that adds a paired sensitive `cluster_profile_secrets` var.
  EOT
  type = map(object({
    name        = string
    description = optional(string, null)

    # Governance override policy: which setting groups a bound cluster may
    # override locally. Values per the v4 clustermgmt profile API.
    allowed_overrides     = optional(list(string), [])
    nfs_subnet_white_list = optional(list(string), [])

    # Association INTENT: cluster NAMES this profile should apply to. Resolved
    # to ext_ids and exposed via cluster_profile_cluster_associations; NOT
    # passed to the resource (2.4.2 has no association input — see var docs).
    clusters = optional(list(string), [])

    # DNS name servers. Each entry sets exactly one of ipv4 / ipv6.
    name_server_ip_list = optional(list(object({
      ipv4 = optional(object({
        value         = string
        prefix_length = optional(number, null)
      }), null)
      ipv6 = optional(object({
        value         = string
        prefix_length = optional(number, null)
      }), null)
    })), [])

    # NTP servers. Each entry sets exactly one of fqdn / ipv4 / ipv6.
    ntp_server_ip_list = optional(list(object({
      fqdn = optional(object({
        value = string
      }), null)
      ipv4 = optional(object({
        value         = string
        prefix_length = optional(number, null)
      }), null)
      ipv6 = optional(object({
        value         = string
        prefix_length = optional(number, null)
      }), null)
    })), [])

    # Remote syslog (rsyslog) servers.
    rsyslog_server_list = optional(list(object({
      server_name      = string
      port             = number
      network_protocol = string # UDP, TCP, RELP, TLS (per v4 API)
      ip_address = optional(object({
        ipv4 = optional(object({
          value         = string
          prefix_length = optional(number, null)
        }), null)
        ipv6 = optional(object({
          value         = string
          prefix_length = optional(number, null)
        }), null)
      }), null)
      modules = optional(list(object({
        name                     = string
        log_severity_level       = string
        should_log_monitor_files = optional(bool, null)
      })), [])
    })), [])

    # Pulse (telemetry) configuration.
    pulse_status = optional(object({
      is_enabled          = optional(bool, null)
      pii_scrubbing_level = optional(string, null)
    }), null)
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.cluster_profiles : length(trimspace(v.name)) > 0
    ])
    error_message = "Each cluster profile must define a non-empty 'name'."
  }

  validation {
    condition = alltrue([
      for k, v in var.cluster_profiles : alltrue([
        for o in v.allowed_overrides :
        contains(["NFS_SUBNET_WHITELIST_CONFIG", "NTP_SERVER_CONFIG", "SNMP_SERVER_CONFIG", "SMTP_SERVER_CONFIG", "PULSE_CONFIG", "NAME_SERVER_CONFIG", "RSYSLOG_SERVER_CONFIG"], o)
      ])
    ])
    error_message = "Each cluster profile 'allowed_overrides' value must be one of: NFS_SUBNET_WHITELIST_CONFIG, NTP_SERVER_CONFIG, SNMP_SERVER_CONFIG, SMTP_SERVER_CONFIG, PULSE_CONFIG, NAME_SERVER_CONFIG, RSYSLOG_SERVER_CONFIG."
  }
}
