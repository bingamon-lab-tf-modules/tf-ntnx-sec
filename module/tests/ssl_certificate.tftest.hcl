##################################################
# Unit Tests: Cluster SSL Certificates (v2)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks, cluster name->ext_id resolution and output
# wiring at plan time only — no live Prism Central connectivity is required.
# The mocked cluster lookup returns a single cluster named "mock-cluster";
# configurations referencing that name resolve, any other name is treated as
# missing.
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

# Test 1: Empty configuration plans zero SSL certificates.
run "ssl_empty_config" {
  command = plan

  variables {
    ssl_certificates = {}
  }

  assert {
    condition     = output.security_summary.total_ssl_certificates == 0
    error_message = "Expected 0 SSL certificates for an empty map"
  }

  assert {
    condition     = length(output.ssl_certificate_ids) == 0
    error_message = "Expected no SSL certificate IDs for an empty map"
  }
}

# Test 2: A single certificate on a resolvable cluster plans cleanly.
run "ssl_single_certificate" {
  command = plan

  variables {
    ssl_certificates = {
      mock_cluster = {
        cluster_name          = "mock-cluster"
        public_certificate    = "mock-public-certificate"
        ca_chain              = "mock-ca-chain"
        private_key_algorithm = "RSA_2048"
      }
    }
    ssl_certificate_keys = {
      mock_cluster = {
        private_key = "mock-private-key-material"
        passphrase  = "mock-passphrase"
      }
    }
  }

  assert {
    condition     = output.security_summary.total_ssl_certificates == 1
    error_message = "Expected 1 SSL certificate"
  }

  assert {
    condition     = length(output.ssl_certificate_ids) == 1
    error_message = "Expected exactly 1 managed SSL certificate resource"
  }

  assert {
    condition     = output.ssl_certificates["mock_cluster"].cluster_ext_id == "00000000-0000-0000-0000-000000000000"
    error_message = "Expected the certificate to resolve the mocked cluster ext_id"
  }
}

# Test 3: An unknown cluster name fails the resolution check rather than
# producing a null cluster_ext_id.
run "ssl_unknown_cluster_fails_check" {
  command = plan

  variables {
    ssl_certificates = {
      ghost = {
        cluster_name = "does-not-exist"
      }
    }
    ssl_certificate_keys = {
      ghost = {
        private_key = "mock-private-key-material"
      }
    }
  }

  expect_failures = [check.ssl_certificates_resolve_cluster]
}

# Test 4: A certificate with no private-key material fails the keys check.
run "ssl_missing_private_key_fails_check" {
  command = plan

  variables {
    ssl_certificates = {
      mock_cluster = {
        cluster_name       = "mock-cluster"
        public_certificate = "mock-public-certificate"
      }
    }
    ssl_certificate_keys = {}
  }

  expect_failures = [check.ssl_certificate_keys_present]
}

# Test 5: An empty cluster_name fails variable validation.
run "ssl_cluster_name_required" {
  command = plan

  variables {
    ssl_certificates = {
      bad = {
        cluster_name = ""
      }
    }
  }

  expect_failures = [var.ssl_certificates]
}
