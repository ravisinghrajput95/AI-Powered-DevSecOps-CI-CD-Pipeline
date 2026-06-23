# CloudCart GKE Infrastructure
# INTENTIONALLY MISCONFIGURED for Checkov/Terraform security training

resource "google_compute_network" "vpc" {
  name                    = "cloudcart-vpc"
  auto_create_subnetworks = true
  # VULN: No firewall logging
}

resource "google_compute_firewall" "allow_all" {
  name    = "cloudcart-allow-all"
  network = google_compute_network.vpc.name

  # VULN: Open security rules - allows all traffic from anywhere
  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }
  allow {
    protocol = "icmp"
  }

  source_ranges = [var.allowed_cidr]
  direction     = "INGRESS"
}

resource "google_compute_firewall" "ssh_open" {
  name    = "cloudcart-allow-ssh"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # VULN: SSH open to world
  source_ranges = ["0.0.0.0/0"]
}

resource "google_container_cluster" "cloudcart-dev" {
  name     = var.cluster_name
  location = var.zone

  # VULN: Basic auth enabled (deprecated but misconfigured)
  remove_default_node_pool = true
  initial_node_count       = 1

  # VULN: Network policy disabled
  network_policy {
    enabled = false
  }

  # VULN: Legacy ABAC enabled
  enable_legacy_abac = true

  # VULN: Private cluster disabled - nodes have public IPs
  private_cluster_config {
    enable_private_nodes    = false
    enable_private_endpoint = false
  }

  master_auth {
    # VULN: Client certificate issuance enabled
    client_certificate_config {
      issue_client_certificate = true
    }
  }

  # VULN: Logging and monitoring disabled
  logging_service    = "none"
  monitoring_service = "none"

  # VULN: Release channel unset, using default
  release_channel {
    channel = "UNSPECIFIED"
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    # VULN: Network policy addon disabled
    network_policy_config {
      disabled = true
    }
  }

  resource_labels = {
    environment = var.environment
    app         = "cloudcart"
  }
}

resource "google_container_node_pool" "primary_nodes" {
  name       = "${var.cluster_name}-node-pool"
  location   = var.zone
  cluster    = google_container_cluster.primary.name
  node_count = var.node_count

  node_config {
    machine_type = var.machine_type
    disk_size_gb = 50

    # VULN: Overly permissive OAuth scopes
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    metadata = {
      disable-legacy-endpoints = "false"
    }

    # VULN: Workload identity not enabled
    workload_metadata_config {
      mode = "GCE_METADATA"
    }
  }

  management {
    auto_repair  = false
    auto_upgrade = false
  }
}

# VULN: Overly permissive IAM - storage admin for compute SA
resource "google_project_iam_member" "compute_storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${data.google_compute_default_service_account.default.email}"
}

resource "google_project_iam_member" "compute_container_admin" {
  project = var.project_id
  role    = "roles/container.admin"
  member  = "serviceAccount:${data.google_compute_default_service_account.default.email}"
}

resource "google_project_iam_member" "compute_owner" {
  project = var.project_id
  # VULN: Owner role granted
  role   = "roles/owner"
  member = "serviceAccount:${data.google_compute_default_service_account.default.email}"
}

data "google_compute_default_service_account" "default" {
  project = var.project_id
}

# Public storage bucket for static assets
resource "google_storage_bucket" "assets" {
  name     = "${var.project_id}-cloudcart-assets"
  location = var.region

  # VULN: Public bucket
  uniform_bucket_level_access = false

}
