locals {

  ##################################################
  # Network Security Policies
  ##################################################

  # Isolation policies
  isolation_policies = {
    for k, v in var.network_security_policies : k => v if v.type == "ISOLATION"
  }

  # Application policies
  application_policies = {
    for k, v in var.network_security_policies : k => v if v.type == "APPLICATION"
  }

  # Quarantine policies
  quarantine_policies = {
    for k, v in var.network_security_policies : k => v if v.type == "QUARANTINE"
  }

  ##################################################
  # Key Management Servers
  ##################################################

  # Key management servers grouped by access-information type (summary only).
  azure_key_management_servers = {
    for k, v in var.key_management_servers : k => v if v.azure != null
  }

  kmip_key_management_servers = {
    for k, v in var.key_management_servers : k => v if v.kmip != null
  }

  ##################################################
  # Cluster SSL Certificates (v2)
  ##################################################

  # Distinct cluster names referenced by the configured SSL certificates. When
  # no certificates are configured this is empty, so no cluster lookups run and
  # the module plans without live Prism Central connectivity.
  ssl_certificate_cluster_names = distinct([for k, v in var.ssl_certificates : v.cluster_name])

  # Resolve each referenced cluster name to its ext_id via nutanix_clusters_v2.
  # The lookup is filtered by name; we additionally require the returned
  # entity's name to match the request so a partial/no match yields null rather
  # than a wrong ext_id.
  ssl_certificate_cluster_ext_ids = {
    for name in local.ssl_certificate_cluster_names :
    name => try([
      for e in data.nutanix_clusters_v2.ssl_certificate_cluster[name].cluster_entities :
      e.ext_id if e.name == name
    ][0], null)
  }

  # Cluster names that failed to resolve to an ext_id (surfaced by the
  # ssl_certificates_resolve_cluster check).
  ssl_certificate_missing_clusters = distinct([
    for k, v in var.ssl_certificates :
    v.cluster_name if lookup(local.ssl_certificate_cluster_ext_ids, v.cluster_name, null) == null
  ])

  # Only certificates whose cluster resolved get a managed resource; unresolved
  # entries never reach the provider with a null cluster_ext_id.
  ssl_certificate_existing = {
    for k, v in var.ssl_certificates :
    k => v if lookup(local.ssl_certificate_cluster_ext_ids, v.cluster_name, null) != null
  }

  # Resolved cluster ext_id per certificate key (drives the gated existing-cert
  # data lookup).
  ssl_certificate_cluster_ext_id_by_key = {
    for k, v in local.ssl_certificate_existing :
    k => local.ssl_certificate_cluster_ext_ids[v.cluster_name]
  }

  ##################################################
  # System-Account Password Changes (v2)
  ##################################################

  # The set of request keys that have a new_password supplied in the sensitive
  # password_change_secrets map. Only the KEYS are declassified with
  # nonsensitive() — they are operator-chosen rotation triggers that already
  # appear in the non-secret var.password_change_requests, so no password
  # material is exposed. This keeps the for_each below non-sensitive (a sensitive
  # value cannot be a for_each argument).
  password_change_secret_keys = nonsensitive(toset([
    for k, v in var.password_change_secrets : k if v.new_password != null
  ]))

  # Only requests that have a matching new_password get a managed resource.
  # new_password is a required provider attribute, so a request without its
  # secret would otherwise hard-error; excluding it here lets the
  # password_change_secrets_present check surface a clear, actionable message.
  password_change_requests_ready = {
    for k, v in var.password_change_requests :
    k => v if contains(local.password_change_secret_keys, k)
  }

  ##################################################
  # Cluster Configuration Profiles (v2)
  ##################################################

  # Distinct cluster names referenced as association intent across all profiles.
  # When no profile references a cluster this is empty, so no cluster lookups run
  # and the module plans without live Prism Central connectivity.
  cluster_profile_cluster_names = distinct(flatten([
    for k, v in var.cluster_profiles : v.clusters
  ]))

  # Resolve each referenced cluster name to its ext_id via nutanix_clusters_v2.
  # The lookup is filtered by name; we additionally require the returned entity's
  # name to match the request so a partial/no match yields null rather than a
  # wrong ext_id.
  cluster_profile_cluster_ext_ids = {
    for name in local.cluster_profile_cluster_names :
    name => try([
      for e in data.nutanix_clusters_v2.cluster_profile_cluster[name].cluster_entities :
      e.ext_id if e.name == name
    ][0], null)
  }

  # Cluster names referenced by a profile that failed to resolve to an ext_id
  # (surfaced by the cluster_profiles_resolve_clusters check).
  cluster_profile_missing_clusters = distinct(flatten([
    for k, v in var.cluster_profiles : [
      for name in v.clusters :
      name if lookup(local.cluster_profile_cluster_ext_ids, name, null) == null
    ]
  ]))

  # Per-profile resolved cluster ext_ids (association intent → ext_ids). The
  # 2.4.2 nutanix_cluster_profile_v2 resource has no association input; this map
  # is exposed as an output for the cluster/PE module to bind cluster-side via
  # cluster_profile_ext_id. Unresolved names are dropped here and flagged by the
  # cluster_profiles_resolve_clusters check.
  cluster_profile_cluster_associations = {
    for k, v in var.cluster_profiles :
    k => [
      for name in v.clusters :
      local.cluster_profile_cluster_ext_ids[name]
      if lookup(local.cluster_profile_cluster_ext_ids, name, null) != null
    ]
  }
}
