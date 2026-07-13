##################################################
# Unit Tests: System-Account Password Changes (v2)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks and output wiring at plan time only — no live
# Prism Central connectivity is required. The password_change_request_v2
# resource models a one-shot rotation action; these tests confirm the module
# wires the non-secret account reference and the sensitive password material
# without ever exposing the password in YAML-facing inputs or outputs.
mock_provider "nutanix" {}

#########################
# Tests
#########################

# Test 1: Empty configuration plans zero password change requests.
run "password_change_empty_config" {
  command = plan

  variables {
    password_change_requests = {}
  }

  assert {
    condition     = output.security_summary.total_password_change_requests == 0
    error_message = "Expected 0 password change requests for an empty map"
  }

  assert {
    condition     = length(output.password_change_request_ids) == 0
    error_message = "Expected no password change request IDs for an empty map"
  }
}

# Test 2: A single request with a matching secret plans exactly one rotation and
# echoes only metadata (the account ext_id), never the password.
run "password_change_single" {
  command = plan

  variables {
    password_change_requests = {
      rotate_2026_q3_admin = {
        ext_id = "00000000-0000-0000-0000-000000000000"
      }
    }
    password_change_secrets = {
      rotate_2026_q3_admin = {
        new_password = "mock-new-password"
      }
    }
  }

  assert {
    condition     = output.security_summary.total_password_change_requests == 1
    error_message = "Expected 1 password change request"
  }

  assert {
    condition     = length(output.password_change_request_ids) == 1
    error_message = "Expected exactly 1 managed password change request resource"
  }

  assert {
    condition     = output.password_change_requests["rotate_2026_q3_admin"].ext_id == "00000000-0000-0000-0000-000000000000"
    error_message = "Expected the request to carry the configured account ext_id"
  }
}

# Test 3: A request supplying both new and current passwords plans cleanly (the
# optional current_password is threaded through from the sensitive map).
run "password_change_with_current_password" {
  command = plan

  variables {
    password_change_requests = {
      rotate_svc_account = {
        ext_id = "11111111-1111-1111-1111-111111111111"
      }
    }
    password_change_secrets = {
      rotate_svc_account = {
        new_password     = "mock-new-password"
        current_password = "mock-current-password"
      }
    }
  }

  assert {
    condition     = length(output.password_change_request_ids) == 1
    error_message = "Expected the request with a current_password to plan"
  }
}

# Test 4: A request with no matching secret fails the parity check (and produces
# no resource, so there is no raw required-argument error).
run "password_change_missing_secret_fails_check" {
  command = plan

  variables {
    password_change_requests = {
      orphan = {
        ext_id = "22222222-2222-2222-2222-222222222222"
      }
    }
    password_change_secrets = {}
  }

  expect_failures = [check.password_change_secrets_present]
}

# Test 5: An empty ext_id fails variable validation.
run "password_change_requires_ext_id" {
  command = plan

  variables {
    password_change_requests = {
      bad = {
        ext_id = ""
      }
    }
  }

  expect_failures = [var.password_change_requests]
}
