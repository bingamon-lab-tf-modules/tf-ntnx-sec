##################################################
# Data Sources for Security
##################################################

# Lookup existing categories
data "nutanix_categories_v2" "existing_categories" {}

# Lookup existing network security policies
data "nutanix_network_security_policies_v2" "existing_policies" {}
