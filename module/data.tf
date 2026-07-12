##################################################
# Data Sources for Security
##################################################

# Lookup existing categories
data "nutanix_categories_v2" "existing_categories" {}

# Lookup existing network security policies
data "nutanix_network_security_policies_v2" "existing_policies" {}

##################################################
# Address Groups (v2 - Flow)
##################################################

# Gated read-only lookup of existing Flow address groups. Disabled by default
# (enable_data_lookups = false) so the module plans without live Prism Central
# connectivity; enable it to reconcile against already-defined address groups.
data "nutanix_address_groups_v2" "existing_address_groups" {
  count = var.enable_data_lookups ? 1 : 0
}

##################################################
# Service Groups (v2 - Flow)
##################################################

# Gated read-only lookup of existing Flow service groups. Disabled by default
# (enable_data_lookups = false) so the module plans without live Prism Central
# connectivity; enable it to reconcile against already-defined service groups.
data "nutanix_service_groups_v2" "existing_service_groups" {
  count = var.enable_data_lookups ? 1 : 0
}

##################################################
# Key Management Servers (v2)
##################################################

# Gated read-only lookup of existing key management servers. Disabled by default
# (enable_data_lookups = false) so the module plans without live Prism Central
# connectivity; enable it when reconciling against already-registered servers.
data "nutanix_key_management_servers_v2" "existing_key_management_servers" {
  count = var.enable_data_lookups ? 1 : 0
}

##################################################
# Cluster SSL Certificates (v2)
##################################################

# Resolve each configured SSL-certificate cluster name to its ext_id. Runs once
# per distinct cluster name; when no certificates are configured the for_each is
# empty and no lookup is performed (module plans without live connectivity).
data "nutanix_clusters_v2" "ssl_certificate_cluster" {
  for_each = toset(local.ssl_certificate_cluster_names)

  limit  = 1
  filter = "name eq '${each.value}'"
}

# Gated read-only lookup of the SSL certificate currently installed on each
# managed cluster. Disabled by default (enable_data_lookups = false); enable it
# to reconcile against the certificate already present on the cluster.
data "nutanix_ssl_certificate_v2" "existing_ssl_certificate" {
  for_each = var.enable_data_lookups ? local.ssl_certificate_cluster_ext_id_by_key : {}

  cluster_ext_id = each.value
}
