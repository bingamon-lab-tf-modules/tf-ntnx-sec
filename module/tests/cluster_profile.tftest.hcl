##################################################
# Unit Tests: Cluster Configuration Profiles (v2)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks, cluster name->ext_id resolution (association
# intent) and output wiring at plan time only — no live Prism Central
# connectivity is required. The mocked cluster lookup returns a single cluster
# named "mock-cluster"; profiles referencing that name resolve, any other name
# is treated as missing.
mock_provider "nutanix" {

  mock_data "nutanix_clusters_v2" {
    defaults = {
      cluster_entities = [
        {
          ext_id                   = "00000000-0000-0000-0000-000000000000"
          name                     = "mock-cluster"
          backup_eligibility_score = 0
          categories               = []
          cluster_profile_ext_id   = ""
          container_name           = ""
          expand                   = ""
          inefficient_vm_count     = 0
          links                    = []
          network                  = []
          nodes                    = []
          tenant_id                = ""
          upgrade_status           = ""
          vm_count                 = 0
          config                   = []
        }
      ]
    }
  }
}

#########################
# Tests
#########################

# Test 1: Empty configuration plans zero cluster profiles.
run "cp_empty_config" {
  command = plan

  variables {
    cluster_profiles = {}
  }

  assert {
    condition     = output.security_summary.total_cluster_profiles == 0
    error_message = "Expected 0 cluster profiles for an empty map"
  }

  assert {
    condition     = length(output.cluster_profile_ids) == 0
    error_message = "Expected no cluster profile IDs for an empty map"
  }
}

# Test 2: A profile with settings and a resolvable cluster plans cleanly and
# resolves the association intent to the mocked cluster ext_id.
run "cp_single_profile_resolves_cluster" {
  command = plan

  variables {
    cluster_profiles = {
      baseline = {
        name                  = "baseline"
        description           = "Org baseline cluster settings"
        allowed_overrides     = ["NTP_SERVER_CONFIG", "NAME_SERVER_CONFIG"]
        nfs_subnet_white_list = ["10.0.0.0/255.0.0.0"]
        clusters              = ["mock-cluster"]

        name_server_ip_list = [
          { ipv4 = { value = "10.0.0.53" } },
        ]

        ntp_server_ip_list = [
          { fqdn = { value = "pool.ntp.org" } },
          { ipv4 = { value = "10.0.0.123" } },
        ]

        rsyslog_server_list = [
          {
            server_name      = "central-syslog"
            port             = 514
            network_protocol = "TCP"
            ip_address       = { ipv4 = { value = "10.0.0.99" } }
            modules          = [{ name = "ACROPOLIS", log_severity_level = "INFO" }]
          },
        ]

        pulse_status = {
          is_enabled          = true
          pii_scrubbing_level = "DEFAULT"
        }
      }
    }
  }

  assert {
    condition     = output.security_summary.total_cluster_profiles == 1
    error_message = "Expected 1 cluster profile"
  }

  assert {
    condition     = length(output.cluster_profile_ids) == 1
    error_message = "Expected exactly 1 managed cluster profile resource"
  }

  assert {
    condition     = contains(output.cluster_profile_cluster_associations["baseline"], "00000000-0000-0000-0000-000000000000")
    error_message = "Expected the profile to resolve the mocked cluster ext_id as association intent"
  }
}

# Test 3: An unknown cluster name fails the resolution check rather than
# silently dropping to a null ext_id.
run "cp_unknown_cluster_fails_check" {
  command = plan

  variables {
    cluster_profiles = {
      ghost = {
        name     = "ghost"
        clusters = ["does-not-exist"]
      }
    }
  }

  expect_failures = [check.cluster_profiles_resolve_clusters]
}

# Test 4: An invalid allowed_overrides value fails variable validation.
run "cp_invalid_allowed_override" {
  command = plan

  variables {
    cluster_profiles = {
      bad = {
        name              = "bad"
        allowed_overrides = ["NOT_A_REAL_OVERRIDE"]
      }
    }
  }

  expect_failures = [var.cluster_profiles]
}

# Test 5: An empty name fails variable validation.
run "cp_name_required" {
  command = plan

  variables {
    cluster_profiles = {
      blank = {
        name = ""
      }
    }
  }

  expect_failures = [var.cluster_profiles]
}
