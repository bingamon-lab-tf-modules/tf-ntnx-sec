##################################################
# Unit Tests: Key Management Servers (v2)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks and output wiring at plan time only — no live
# Prism Central connectivity is required.
mock_provider "nutanix" {}

#########################
# Tests
#########################

# Test 1: Empty configuration plans zero key management servers.
run "kms_empty_config" {
  command = plan

  variables {
    key_management_servers = {}
  }

  assert {
    condition     = output.security_summary.total_key_management_servers == 0
    error_message = "Expected 0 key management servers for an empty map"
  }

  assert {
    condition     = length(output.key_management_server_ids) == 0
    error_message = "Expected no key management server IDs for an empty map"
  }
}

# Test 2: A single Azure Key Vault registration plans cleanly.
run "kms_azure_registration" {
  command = plan

  variables {
    key_management_servers = {
      vault_kms = {
        name = "vault-kms"
        azure = {
          client_id              = "00000000-0000-0000-0000-000000000000"
          tenant_id              = "11111111-1111-1111-1111-111111111111"
          key_id                 = "kms-key"
          endpoint_url           = "https://vault.example.com"
          credential_expiry_date = "2027-01-01"
        }
      }
    }
    key_management_server_credentials = {
      vault_kms = {
        client_secret = "mock-client-secret"
      }
    }
  }

  assert {
    condition     = output.security_summary.total_key_management_servers == 1
    error_message = "Expected 1 key management server"
  }

  assert {
    condition     = output.security_summary.azure_key_management_servers == 1
    error_message = "Expected 1 Azure key management server"
  }

  assert {
    condition     = output.key_management_servers["vault_kms"].name == "vault-kms"
    error_message = "Expected KMS name 'vault-kms'"
  }
}

# Test 3: A single KMIP registration plans cleanly.
run "kms_kmip_registration" {
  command = plan

  variables {
    key_management_servers = {
      kmip_kms = {
        name = "kmip-kms"
        kmip = {
          ca_name = "root-ca"
          endpoints = [
            {
              port = 5696
              ipv4 = [{ value = "10.0.0.10" }]
            }
          ]
        }
      }
    }
    key_management_server_credentials = {
      kmip_kms = {
        ca_pem      = "mock-ca-pem"
        cert_pem    = "mock-cert-pem"
        private_key = "mock-private-key"
      }
    }
  }

  assert {
    condition     = output.security_summary.kmip_key_management_servers == 1
    error_message = "Expected 1 KMIP key management server"
  }

  assert {
    condition     = output.key_management_servers["kmip_kms"].name == "kmip-kms"
    error_message = "Expected KMS name 'kmip-kms'"
  }
}

# Test 4: A KMS with neither access-information block fails validation.
run "kms_requires_exactly_one_type" {
  command = plan

  variables {
    key_management_servers = {
      bad = {
        name = "bad-kms"
      }
    }
  }

  expect_failures = [var.key_management_servers]
}

# Test 5: A KMS with BOTH access-information blocks fails validation.
run "kms_rejects_both_types" {
  command = plan

  variables {
    key_management_servers = {
      bad = {
        name = "bad-kms"
        azure = {
          client_id              = "00000000-0000-0000-0000-000000000000"
          tenant_id              = "11111111-1111-1111-1111-111111111111"
          key_id                 = "kms-key"
          endpoint_url           = "https://vault.example.com"
          credential_expiry_date = "2027-01-01"
        }
        kmip = {
          ca_name = "root-ca"
          endpoints = [
            {
              port = 5696
              ipv4 = [{ value = "10.0.0.10" }]
            }
          ]
        }
      }
    }
  }

  expect_failures = [var.key_management_servers]
}
