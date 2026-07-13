##################################################
# Unit Tests: Entity Groups (v2 - Flow microsegmentation)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks, and output wiring at plan time only — no live
# Prism Central connectivity is required. The gated entity-group lookup is
# disabled by default (enable_data_lookups = false), so no mock data is needed.
mock_provider "nutanix" {}

#########################
# Tests
#########################

# Test 1: Empty configuration plans zero entity groups.
run "entity_groups_empty_config" {
  command = plan

  variables {
    entity_groups = {}
  }

  assert {
    condition     = output.security_summary.total_entity_groups == 0
    error_message = "Expected 0 entity groups for an empty map"
  }

  assert {
    condition     = length(output.entity_group_ids) == 0
    error_message = "Expected no entity group IDs for an empty configuration"
  }
}

# Test 2: A bare entity group (name + description, no config) is valid and plans.
run "entity_groups_simple" {
  command = plan

  variables {
    entity_groups = {
      prod_scope = {
        name        = "prod-scope"
        description = "Production microseg scope"
      }
    }
  }

  assert {
    condition     = output.security_summary.total_entity_groups == 1
    error_message = "Expected 1 entity group"
  }

  assert {
    condition     = length(output.entity_group_ids) == 1
    error_message = "Expected exactly 1 managed entity group resource"
  }

  assert {
    condition     = output.entity_groups["prod_scope"].name == "prod-scope"
    error_message = "Expected the prod_scope entity group to carry name 'prod-scope'"
  }
}

# Test 3: An entity group selecting VMs by category and an address group by IP
# (both valid pairs, with inline addresses and ranges) plans cleanly and is
# reflected in the outputs.
run "entity_groups_allowed_config" {
  command = plan

  variables {
    entity_groups = {
      web_tier = {
        name        = "web-tier"
        description = "Web VMs plus a trusted admin range"
        allowed_config = {
          entities = [
            {
              type              = "VM"
              selected_by       = "CATEGORY_EXT_ID"
              reference_ext_ids = ["11111111-1111-1111-1111-111111111111"]
            },
            {
              type        = "ADDRESS_GROUP"
              selected_by = "IP_VALUES"
              ipv4_addresses = [
                { value = "10.0.0.0", prefix_length = 24 },
              ]
              ipv4_ranges = [
                { start_ip = "192.168.1.1", end_ip = "192.168.1.10" },
              ]
            },
          ]
        }
      }
    }
  }

  assert {
    condition     = length(output.entity_group_ids) == 1
    error_message = "Expected the allowed_config entity group to plan"
  }

  assert {
    condition     = output.entity_groups["web_tier"].name == "web-tier"
    error_message = "Expected the web_tier entity group to carry name 'web-tier'"
  }
}

# Test 4: An except_config entity excluding an address group by IP range (the
# only shape the 2.4.2 provider permits for except_config) plans cleanly.
run "entity_groups_except_config" {
  command = plan

  variables {
    entity_groups = {
      all_but_admin = {
        name = "all-but-admin"
        allowed_config = {
          entities = [
            {
              type              = "SUBNET"
              selected_by       = "CATEGORY_EXT_ID"
              reference_ext_ids = ["22222222-2222-2222-2222-222222222222"]
            },
          ]
        }
        except_config = {
          entities = [
            {
              type        = "ADDRESS_GROUP"
              selected_by = "IP_VALUES"
              ipv4_ranges = [
                { start_ip = "10.0.0.240", end_ip = "10.0.0.254" },
              ]
            },
          ]
        }
      }
    }
  }

  assert {
    condition     = length(output.entity_group_ids) == 1
    error_message = "Expected the except_config entity group to plan"
  }
}

# Test 5: An unknown entity 'type' fails variable validation.
run "entity_groups_invalid_type" {
  command = plan

  variables {
    entity_groups = {
      bad = {
        name = "bad"
        allowed_config = {
          entities = [
            { type = "SERVERS", selected_by = "CATEGORY_EXT_ID" },
          ]
        }
      }
    }
  }

  expect_failures = [var.entity_groups]
}

# Test 6: A valid type and selected_by used as an unsupported pair (VM by
# IP_VALUES) fails the (selected_by, type) pair validation.
run "entity_groups_invalid_pair" {
  command = plan

  variables {
    entity_groups = {
      bad = {
        name = "bad"
        allowed_config = {
          entities = [
            { type = "VM", selected_by = "IP_VALUES" },
          ]
        }
      }
    }
  }

  expect_failures = [var.entity_groups]
}

# Test 7: An except_config entity of a non-address-group type (VM) fails the
# narrow except_config validation.
run "entity_groups_except_rejects_non_address_group" {
  command = plan

  variables {
    entity_groups = {
      bad = {
        name = "bad"
        except_config = {
          entities = [
            { type = "VM", selected_by = "IP_VALUES" },
          ]
        }
      }
    }
  }

  expect_failures = [var.entity_groups]
}

# Test 8: An out-of-range ipv4 prefix_length fails the prefix-length validation.
run "entity_groups_invalid_prefix" {
  command = plan

  variables {
    entity_groups = {
      bad = {
        name = "bad"
        allowed_config = {
          entities = [
            {
              type        = "ADDRESS_GROUP"
              selected_by = "IP_VALUES"
              ipv4_addresses = [
                { value = "10.0.0.0", prefix_length = 40 },
              ]
            },
          ]
        }
      }
    }
  }

  expect_failures = [var.entity_groups]
}
