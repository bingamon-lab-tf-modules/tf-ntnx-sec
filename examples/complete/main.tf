##################################################
# Complete Example - tf-ntnx-sec
#
# NOTE: This example targets the CURRENT module schema (v1 category
# resources + v2/v4 network security policies). The categories v1 -> v2
# migration is tracked separately and this example will be re-authored
# once that lands. Do not treat this schema as final.
##################################################

terraform {
  required_version = ">= 1.9.0"

  required_providers {
    nutanix = {
      source  = "nutanix/nutanix"
      version = ">= 2.4.2"
    }
  }
}

provider "nutanix" {
  username = var.nutanix_username
  password = var.nutanix_password
  endpoint = var.nutanix_endpoint
  insecure = var.nutanix_insecure
}

module "security" {
  source = "../../module"

  # Categories (v1)
  category_keys   = var.category_keys
  category_values = var.category_values

  # Network Security Policies (v2 - Flow)
  network_security_policies = var.network_security_policies
}
