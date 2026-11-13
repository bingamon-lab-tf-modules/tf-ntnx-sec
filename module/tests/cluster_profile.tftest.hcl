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
          network = [
            {
              backplane                  = []
              external_address           = []
              external_data_services_ip  = []
              external_subnet            = ""
              fqdn                       = ""
              http_proxy_list            = []
              http_proxy_white_list      = []
              internal_subnet            = ""
              key_management_server_type = ""
              management_server = [
                {
                  ip             = []
                  is_drs_enabled = false
                  is_in_use      = true
                  is_registered  = true
                  type           = "VCENTER"
                }
              ]
              masquerading_ip       = []
              masquerading_port     = 0
              name_server_ip_list   = []
              nfs_subnet_white_list = []
              ntp_server_ip_list    = []
              smtp_server           = []
            }
          ]
          nodes          = []
          tenant_id      = ""
          upgrade_status = ""
          vm_count       = 0
          config         = []
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

# Test 6: Gated read-only data lookups (enable_data_lookups = true) plan
# cleanly against the v2.5.1 schemas, including cluster_profiles[*].clusters[*].config_drifts
# as a list of strings.
run "cp_data_lookups_enabled" {
  command = plan

  variables {
    enable_data_lookups = true
    cluster_profiles = {
      baseline = {
        name     = "baseline"
        clusters = ["mock-cluster"]
      }
    }
  }

  override_data {
    target = data.nutanix_cluster_profiles_v2.existing_cluster_profiles[0]
    values = {
      cluster_profiles = [
        {
          ext_id                = "11111111-1111-1111-1111-111111111111"
          name                  = "existing-baseline"
          description           = "Existing profile"
          allowed_overrides     = ["NTP_SERVER_CONFIG"]
          cluster_count         = 1
          drifted_cluster_count = 1
          clusters = [
            {
              ext_id           = "00000000-0000-0000-0000-000000000000"
              is_compliant     = false
              last_synced_time = "2026-01-01T00:00:00Z"
              config_drifts    = ["NTP_SERVER_CONFIG"]
            }
          ]
          create_time                                 = "2026-01-01T00:00:00Z"
          created_by                                  = "admin"
          fault_tolerance_config                      = []
          http_proxy_config                           = []
          last_update_time                            = "2026-01-01T00:00:00Z"
          last_updated_by                             = "admin"
          links                                       = []
          name_server_ip_list                         = []
          nfs_subnet_white_list                       = []
          ntp_server_config_list                      = []
          ntp_server_ip_list                          = []
          pulse_status                                = []
          rebuild_reservation_config                  = []
          resilient_capacity_warning_threshold_config = []
          rsyslog_server_list                         = []
          smtp_server                                 = []
          snmp_config                                 = []
          tenant_id                                   = ""
        }
      ]
    }
  }

  assert {
    condition     = contains(output.cluster_profile_cluster_associations["baseline"], "00000000-0000-0000-0000-000000000000")
    error_message = "Expected cluster association resolution to succeed with enable_data_lookups = true"
  }
}
