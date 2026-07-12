##################################################
# Data Sources for Security
##################################################

# Lookup existing categories
data "nutanix_categories_v2" "existing_categories" {}

# Lookup existing network security policies
data "nutanix_network_security_policies_v2" "existing_policies" {}

##################################################
# Key Management Servers (v2)
##################################################

# Gated read-only lookup of existing key management servers. Disabled by default
# (enable_data_lookups = false) so the module plans without live Prism Central
# connectivity; enable it when reconciling against already-registered servers.
data "nutanix_key_management_servers_v2" "existing_key_management_servers" {
  count = var.enable_data_lookups ? 1 : 0
}
