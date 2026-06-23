variable "project_id" {
  description = "GCP Project ID"
  type        = string
  default     = "cloudcart-devsecops"
}

variable "region" {
  description = "GCP Region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP Zone"
  type        = string
  default     = "us-central1-a"
}

variable "cluster_name" {
  description = "GKE Cluster name"
  type        = string
  default     = "cloudcart-dev"
}

variable "node_count" {
  description = "Number of GKE nodes"
  type        = number
  default     = 3
}

variable "machine_type" {
  description = "GKE node machine type"
  type        = string
  default     = "e2-medium"
}

variable "allowed_cidr" {
  description = "CIDR allowed to access cluster"
  type        = string
  # VULN: Open to entire internet
  default     = "0.0.0.0/0"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}
