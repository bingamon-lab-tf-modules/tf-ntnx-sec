##################################################
# Example - tf-ntnx-sec
#
# Manages Nutanix categories (v2) and a Flow network security policy
# (v2). Categories model an environment axis and an application-tier
# axis; the policy secures the web/db application tiers.
##################################################

terraform {
  required_version = ">= 1.9.0"
}

module "tf-ntnx-sec" {
  source = "git::https://github.com/bingamon-lab-tf-modules/tf-ntnx-sec.git//module?ref=v0.1.0"

  ##################################################
  # Categories (v2)
  #
  # Each entry becomes one nutanix_category_v2 (key + value +
  # description). Reusing a key across entries (here "app") is fine; the
  # v2 API has no separate category-key resource.
  ##################################################
  categories = {
    env_production = {
      key         = "environment"
      value       = "production"
      description = "Production workloads"
    }
    app_web = {
      key         = "app"
      value       = "web"
      description = "Web-tier application servers"
    }
    app_db = {
      key         = "app"
      value       = "db"
      description = "Database-tier application servers"
    }
  }

  ##################################################
  # Network Security Policies (v2 - Flow)
  #
  # One APPLICATION policy in MONITOR state with two rules:
  #   1. INTRA_GROUP  - allow web servers to talk to each other.
  #   2. APPLICATION  - allow inbound HTTP/HTTPS from the web tier into
  #                     the db tier (plus an app service group and an
  #                     allowed source address group).
  #
  # Category / service-group / address-group references are entity
  # ext_ids (UUIDs). Categories created in this same module call cannot
  # be referenced here without a dependency cycle, so the UUIDs below
  # are illustrative placeholders — in practice wire real ext_ids from a
  # separate module instance, this module's `category_ids` output, or a
  # nutanix_categories_v2 / nutanix_service_groups_v2 data lookup.
  ##################################################
  network_security_policies = {
    web_app = {
      name        = "web-app-policy"
      description = "Secure the web application tier"
      type        = "APPLICATION"
      state       = "MONITOR"

      is_ipv6_traffic_allowed = false
      is_hitlog_enabled       = true

      rules = [
        {
          description = "Allow intra web-tier traffic"
          type        = "INTRA_GROUP"
          spec = {
            intra_entity_group_rule_spec = {
              secured_group_action              = "ALLOW"
              secured_group_category_references = ["11111111-1111-1111-1111-111111111111"] # app/web
            }
          }
        },
        {
          description = "Allow inbound web -> db on HTTP/HTTPS"
          type        = "APPLICATION"
          spec = {
            application_rule_spec = {
              secured_group_category_references = ["22222222-2222-2222-2222-222222222222"] # app/db (destination)
              src_category_references           = ["11111111-1111-1111-1111-111111111111"] # app/web (source)
              src_address_group_references      = ["33333333-3333-3333-3333-333333333333"] # trusted-admin subnet
              service_group_references          = ["44444444-4444-4444-4444-444444444444"] # web-app service group

              tcp_services = [
                { start_port = 80, end_port = 80 },
                { start_port = 443, end_port = 443 },
              ]
            }
          }
        },
      ]
    }
  }
}

##################################################
# Outputs
##################################################

output "categories" {
  description = "Created categories (key/value pairs) and their ext_ids."
  value       = module.tf-ntnx-sec.categories
}

output "network_security_policies" {
  description = "Created network security policies."
  value       = module.tf-ntnx-sec.network_security_policies
}

output "security_summary" {
  description = "Summary of the security resources managed by the module."
  value       = module.tf-ntnx-sec.security_summary
}
