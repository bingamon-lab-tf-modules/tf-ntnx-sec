##################################################
# Unit Tests: Image Placement Policies (v2)
##################################################

#########################
# Mock Data (Nutanix Provider)
#########################

# All Nutanix resources and data sources are mocked; these tests exercise
# variable validation, checks, and output wiring at plan time only — no live
# Prism Central connectivity is required. The gated image-placement-policy
# lookup is disabled by default (enable_data_lookups = false), so no mock data
# is needed for it.
mock_provider "nutanix" {}

#########################
# Tests
#########################

# Test 1: Empty configuration plans zero image placement policies.
run "ipp_empty_config" {
  command = plan

  variables {
    image_placement_policies = {}
  }

  assert {
    condition     = output.security_summary.total_image_placement_policies == 0
    error_message = "Expected 0 image placement policies for an empty map"
  }

  assert {
    condition     = length(output.image_placement_policy_ids) == 0
    error_message = "Expected no image placement policy IDs for an empty map"
  }
}

# Test 2: A single SOFT policy with both category filters plans cleanly.
run "ipp_single_policy" {
  command = plan

  variables {
    image_placement_policies = {
      linux_to_prod = {
        name           = "linux-to-prod"
        description    = "Pin linux images to prod clusters"
        placement_type = "SOFT"

        image_entity_filter = {
          type             = "CATEGORIES_MATCH_ALL"
          category_ext_ids = ["11111111-1111-1111-1111-111111111111"]
        }

        cluster_entity_filter = {
          type             = "CATEGORIES_MATCH_ANY"
          category_ext_ids = ["22222222-2222-2222-2222-222222222222"]
        }
      }
    }
  }

  assert {
    condition     = output.security_summary.total_image_placement_policies == 1
    error_message = "Expected 1 image placement policy"
  }

  assert {
    condition     = length(output.image_placement_policy_ids) == 1
    error_message = "Expected exactly 1 managed image placement policy resource"
  }

  assert {
    condition     = output.image_placement_policies["linux_to_prod"].placement_type == "SOFT"
    error_message = "Expected the policy placement_type to be SOFT"
  }
}

# Test 3: An invalid placement_type is rejected by variable validation with a
# clear message.
run "ipp_invalid_placement_type" {
  command = plan

  variables {
    image_placement_policies = {
      bad = {
        name           = "bad"
        placement_type = "MAYBE"
        image_entity_filter = {
          type             = "CATEGORIES_MATCH_ALL"
          category_ext_ids = ["11111111-1111-1111-1111-111111111111"]
        }
        cluster_entity_filter = {
          type             = "CATEGORIES_MATCH_ALL"
          category_ext_ids = ["22222222-2222-2222-2222-222222222222"]
        }
      }
    }
  }

  expect_failures = [var.image_placement_policies]
}

# Test 4: An invalid filter type is rejected by variable validation.
run "ipp_invalid_filter_type" {
  command = plan

  variables {
    image_placement_policies = {
      bad = {
        name           = "bad"
        placement_type = "HARD"
        image_entity_filter = {
          type             = "MATCH_SOMETHING"
          category_ext_ids = ["11111111-1111-1111-1111-111111111111"]
        }
        cluster_entity_filter = {
          type             = "CATEGORIES_MATCH_ALL"
          category_ext_ids = ["22222222-2222-2222-2222-222222222222"]
        }
      }
    }
  }

  expect_failures = [var.image_placement_policies]
}

# Test 5: A filter with no category_ext_ids fails the filters check.
run "ipp_empty_filter_fails_check" {
  command = plan

  variables {
    image_placement_policies = {
      empty_filter = {
        name           = "empty-filter"
        placement_type = "SOFT"
        image_entity_filter = {
          type             = "CATEGORIES_MATCH_ALL"
          category_ext_ids = []
        }
        cluster_entity_filter = {
          type             = "CATEGORIES_MATCH_ALL"
          category_ext_ids = ["22222222-2222-2222-2222-222222222222"]
        }
      }
    }
  }

  expect_failures = [check.image_placement_policies_have_filters]
}
