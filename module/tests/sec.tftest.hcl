##################################################
# Unit Tests: Categories (v2) + Network Security Policies (v2 - Flow)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks, locals grouping and output wiring at plan time
# only — no live Prism Central connectivity is required. The two read-only
# lookups the module always performs are mocked with empty result sets.
mock_provider "nutanix" {

  # Existing categories lookup (module/data.tf).
  mock_data "nutanix_categories_v2" {
    defaults = {
      categories = []
    }
  }

  # Existing network security policies lookup (module/data.tf).
  mock_data "nutanix_network_security_policies_v2" {
    defaults = {
      network_policies = []
    }
  }
}

#########################
# Tests
#########################

# Test 1: Empty configuration plans zero categories and zero policies.
run "sec_empty_config" {
  command = plan

  variables {
    categories                = {}
    network_security_policies = {}
  }

  assert {
    condition     = output.security_summary.total_categories == 0
    error_message = "Expected 0 categories for an empty map"
  }

  assert {
    condition     = output.security_summary.total_security_policies == 0
    error_message = "Expected 0 network security policies for an empty map"
  }

  assert {
    condition     = length(output.category_ids) == 0 && length(output.network_security_policy_ids) == 0
    error_message = "Expected no category or policy IDs for an empty configuration"
  }
}

# Test 2: A set of categories plans cleanly and is reflected in the outputs.
run "sec_categories" {
  command = plan

  variables {
    categories = {
      env_production = {
        key         = "environment"
        value       = "production"
        description = "Production workloads"
      }
      app_web = {
        key   = "app"
        value = "web"
      }
      app_db = {
        key   = "app"
        value = "db"
      }
    }
    network_security_policies = {}
  }

  assert {
    condition     = output.security_summary.total_categories == 3
    error_message = "Expected 3 categories"
  }

  assert {
    condition     = length(output.category_ids) == 3
    error_message = "Expected exactly 3 managed category resources"
  }

  assert {
    condition     = output.categories["app_web"].key == "app" && output.categories["app_web"].value == "web"
    error_message = "Expected the app_web category to carry key 'app' and value 'web'"
  }
}

# Test 3: An APPLICATION policy with an intra-group rule and an inbound
# application rule (referencing categories, an address group and a service
# group) plans cleanly and is reflected in the outputs.
run "sec_application_policy" {
  command = plan

  variables {
    categories = {
      app_web = { key = "app", value = "web" }
      app_db  = { key = "app", value = "db" }
    }
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
                secured_group_category_references = ["11111111-1111-1111-1111-111111111111"]
              }
            }
          },
          {
            description = "Allow inbound web -> db on HTTP/HTTPS"
            type        = "APPLICATION"
            spec = {
              application_rule_spec = {
                secured_group_category_references = ["22222222-2222-2222-2222-222222222222"]
                src_category_references           = ["11111111-1111-1111-1111-111111111111"]
                src_address_group_references      = ["33333333-3333-3333-3333-333333333333"]
                service_group_references          = ["44444444-4444-4444-4444-444444444444"]
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

  assert {
    condition     = output.security_summary.total_security_policies == 1
    error_message = "Expected 1 network security policy"
  }

  assert {
    condition     = output.security_summary.application_policies == 1
    error_message = "Expected the policy to be counted as an APPLICATION policy"
  }

  assert {
    condition     = output.network_security_policies["web_app"].type == "APPLICATION"
    error_message = "Expected the web_app policy type to be APPLICATION"
  }

  assert {
    condition     = length(output.network_security_policy_ids) == 1
    error_message = "Expected exactly 1 managed network security policy resource"
  }
}

# Test 4: A mix of policy types is grouped correctly by the locals that drive
# the security_summary counts.
run "sec_policy_type_grouping" {
  command = plan

  variables {
    network_security_policies = {
      isolate_env = {
        name  = "isolate-prod-from-dev"
        type  = "ISOLATION"
        state = "ENFORCE"
        rules = [
          {
            type = "TWO_ENV_ISOLATION"
            spec = {
              two_env_isolation_rule_spec = {
                first_isolation_group  = ["11111111-1111-1111-1111-111111111111"]
                second_isolation_group = ["22222222-2222-2222-2222-222222222222"]
              }
            }
          },
        ]
      }
      secure_app = {
        name  = "secure-web-tier"
        type  = "APPLICATION"
        state = "MONITOR"
        rules = [
          {
            type = "INTRA_GROUP"
            spec = {
              intra_entity_group_rule_spec = {
                secured_group_action              = "ALLOW"
                secured_group_category_references = ["33333333-3333-3333-3333-333333333333"]
              }
            }
          },
        ]
      }
    }
  }

  assert {
    condition     = output.security_summary.total_security_policies == 2
    error_message = "Expected 2 network security policies"
  }

  assert {
    condition     = output.security_summary.isolation_policies == 1 && output.security_summary.application_policies == 1
    error_message = "Expected 1 isolation policy and 1 application policy"
  }

  assert {
    condition     = output.security_summary.quarantine_policies == 0
    error_message = "Expected 0 quarantine policies"
  }
}

# Test 5: An invalid policy 'type' enum fails variable validation.
run "sec_invalid_policy_type" {
  command = plan

  variables {
    network_security_policies = {
      bad = {
        name = "bad-policy"
        type = "INVALID"
        rules = [
          {
            type = "INTRA_GROUP"
            spec = {
              intra_entity_group_rule_spec = {
                secured_group_action              = "ALLOW"
                secured_group_category_references = ["11111111-1111-1111-1111-111111111111"]
              }
            }
          },
        ]
      }
    }
  }

  expect_failures = [var.network_security_policies]
}

# Test 6: An invalid policy 'state' enum fails variable validation.
run "sec_invalid_policy_state" {
  command = plan

  variables {
    network_security_policies = {
      bad = {
        name  = "bad-policy"
        type  = "APPLICATION"
        state = "BAD"
        rules = [
          {
            type = "INTRA_GROUP"
            spec = {
              intra_entity_group_rule_spec = {
                secured_group_action              = "ALLOW"
                secured_group_category_references = ["11111111-1111-1111-1111-111111111111"]
              }
            }
          },
        ]
      }
    }
  }

  expect_failures = [var.network_security_policies]
}

# Test 7: A category value containing disallowed characters fails validation.
run "sec_invalid_category_value" {
  command = plan

  variables {
    categories = {
      bad = {
        key   = "app"
        value = "not valid!"
      }
    }
  }

  expect_failures = [var.categories]
}

# Test 8: A rule whose spec sets none of the three rule specs fails the
# exactly-one-spec validation.
run "sec_rule_requires_single_spec" {
  command = plan

  variables {
    network_security_policies = {
      bad = {
        name = "bad-policy"
        type = "APPLICATION"
        rules = [
          {
            type = "APPLICATION"
            spec = {}
          },
        ]
      }
    }
  }

  expect_failures = [var.network_security_policies]
}
