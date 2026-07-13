##################################################
# Unit Tests: Address Groups (v2) + Service Groups (v2 - Flow)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks, and output wiring at plan time only — no live
# Prism Central connectivity is required. The gated address/service group
# lookups are disabled by default (enable_data_lookups = false), so no mock
# data is needed for them.
mock_provider "nutanix" {}

#########################
# Tests
#########################

# Test 1: Empty configuration plans zero address groups and zero service groups.
run "groups_empty_config" {
  command = plan

  variables {
    address_groups = {}
    service_groups = {}
  }

  assert {
    condition     = output.security_summary.total_address_groups == 0
    error_message = "Expected 0 address groups for an empty map"
  }

  assert {
    condition     = output.security_summary.total_service_groups == 0
    error_message = "Expected 0 service groups for an empty map"
  }

  assert {
    condition     = length(output.address_group_ids) == 0 && length(output.service_group_ids) == 0
    error_message = "Expected no address or service group IDs for an empty configuration"
  }
}

# Test 2: One address group (IPv4 members) and one service group (TCP ports)
# plan cleanly and are reflected in the outputs.
run "groups_populated" {
  command = plan

  variables {
    address_groups = {
      mgmt_nets = {
        name        = "mgmt-nets"
        description = "Management networks"
        ipv4_addresses = [
          { value = "10.0.10.0", prefix_length = 24 },
        ]
      }
    }
    service_groups = {
      web = {
        name        = "web"
        description = "HTTP/HTTPS"
        tcp_services = [
          { start_port = 80, end_port = 80 },
          { start_port = 443, end_port = 443 },
        ]
      }
    }
  }

  assert {
    condition     = output.security_summary.total_address_groups == 1
    error_message = "Expected 1 address group"
  }

  assert {
    condition     = output.security_summary.total_service_groups == 1
    error_message = "Expected 1 service group"
  }

  assert {
    condition     = length(output.address_group_ids) == 1 && length(output.service_group_ids) == 1
    error_message = "Expected exactly 1 managed address group and 1 managed service group resource"
  }

  assert {
    condition     = output.address_groups["mgmt_nets"].name == "mgmt-nets"
    error_message = "Expected the mgmt_nets address group to carry name 'mgmt-nets'"
  }

  assert {
    condition     = output.service_groups["web"].name == "web"
    error_message = "Expected the web service group to carry name 'web'"
  }
}

# Test 3: An address group defined by an IP range (rather than IPv4 addresses)
# and a service group with a UDP service and an ICMP service plan cleanly.
run "groups_range_and_mixed_services" {
  command = plan

  variables {
    address_groups = {
      dc_range = {
        name = "dc-range"
        ip_ranges = [
          { start_ip = "10.20.0.1", end_ip = "10.20.0.254" },
        ]
      }
    }
    service_groups = {
      dns_ping = {
        name = "dns-ping"
        udp_services = [
          { start_port = 53, end_port = 53 },
        ]
        icmp_services = [
          { is_all_allowed = true },
        ]
      }
    }
  }

  assert {
    condition     = length(output.address_group_ids) == 1 && length(output.service_group_ids) == 1
    error_message = "Expected the range-based address group and mixed-service service group to plan"
  }
}

# Test 4: An address group with no members fails variable validation.
run "groups_address_requires_member" {
  command = plan

  variables {
    address_groups = {
      empty = {
        name = "empty"
      }
    }
  }

  expect_failures = [var.address_groups]
}

# Test 5: A service group with no services fails variable validation.
run "groups_service_requires_service" {
  command = plan

  variables {
    service_groups = {
      empty = {
        name = "empty"
      }
    }
  }

  expect_failures = [var.service_groups]
}

# Test 6: A service group with an out-of-range / inverted TCP port fails the
# port-range validation.
run "groups_service_port_range_sanity" {
  command = plan

  variables {
    service_groups = {
      bad = {
        name = "bad"
        tcp_services = [
          { start_port = 8080, end_port = 80 },
        ]
      }
    }
  }

  expect_failures = [var.service_groups]
}
