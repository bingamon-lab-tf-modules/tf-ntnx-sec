# Complete Example

This example demonstrates how to use the tf-ntnx-sec module to manage
security resources in Nutanix:

- Category keys and category values (v1 category resources)
- Network security policies (v2 - Flow / v4 API)

> **NOTE:** This example targets the CURRENT module schema (v1 category
> resources + v2/v4 network security policies). The categories v1 -> v2
> migration is tracked separately (lz-paas backlog issue 553) and the final
> example is owned by issue 542; this example will be re-authored once the
> migration lands. Do not treat this schema as final.

## Usage

```hcl
module "security" {
  source = "../../module"

  # Categories (v1)
  category_keys = {
    environment = {
      name        = "Environment"
      description = "Deployment environment"
    }
  }

  category_values = {
    environment_production = {
      category_key = "Environment"
      value        = "Production"
    }
    environment_development = {
      category_key = "Environment"
      value        = "Development"
    }
  }

  # Network Security Policies (v2 - Flow)
  network_security_policies = {
    env_isolation = {
      name        = "isolate-dev-from-prod"
      description = "Isolate development VMs from production VMs"
      type        = "ISOLATION"
      state       = "MONITOR"

      rules = [
        {
          type = "TWO_ENV_ISOLATION"
          spec = {
            two_env_isolation_rule_spec = {
              first_isolation_group  = ["<category-value-ext-id-1>"]
              second_isolation_group = ["<category-value-ext-id-2>"]
            }
          }
        }
      ]
    }

    secure_app = {
      name        = "secure-application"
      description = "Application security policy"
      type        = "APPLICATION"
      state       = "MONITOR"

      rules = [
        {
          type = "APPLICATION"
          spec = {
            application_rule_spec = {
              secured_group_category_references = ["<category-value-ext-id>"]
              src_allow_spec                    = "ALL"
              is_all_protocol_allowed           = true
            }
          }
        }
      ]
    }
  }
}
```

## Requirements

| Name      | Version  |
| --------- | -------- |
| terraform | >= 1.9.0 |
| nutanix   | >= 2.4.2 |

## Inputs

| Name                      | Description                                | Type        | Default |
| ------------------------- | ------------------------------------------ | ----------- | ------- |
| nutanix_username          | Nutanix Prism Central username             | string      | -       |
| nutanix_password          | Nutanix Prism Central password             | string      | -       |
| nutanix_endpoint          | Nutanix Prism Central endpoint             | string      | -       |
| nutanix_insecure          | Skip TLS verification                      | bool        | false   |
| category_keys             | Map of category keys to create             | map(object) | {}      |
| category_values           | Map of category values to create           | map(object) | {}      |
| network_security_policies | Map of network security policies to create | map(object) | {}      |

## Outputs

| Name                        | Description                             |
| --------------------------- | --------------------------------------- |
| category_keys               | Created category keys                   |
| category_key_ids            | Category key IDs                        |
| category_values_managed     | Created category values (managed keys)  |
| category_values_existing    | Created category values (existing keys) |
| network_security_policies   | Created network security policies       |
| network_security_policy_ids | Network security policy external IDs    |

## Notes

- Each network security policy rule `spec` must set exactly one of
  `two_env_isolation_rule_spec`, `application_rule_spec`, or
  `intra_entity_group_rule_spec`.
- `category_values[*].category_key` may reference either a key managed via
  `category_keys` (by its `name`) or an existing category key name in
  Prism Central.
- Policy `state` is one of `SAVE`, `MONITOR`, `ENFORCE`; policy `type` is
  one of `QUARANTINE`, `ISOLATION`, `APPLICATION`.
