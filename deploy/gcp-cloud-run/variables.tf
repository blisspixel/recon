variable "project_id" {
  description = "Google Cloud project that owns the optional recon service."
  type        = string
}

variable "region" {
  description = "Cloud Run region. Choose it for user proximity, policy, and service availability."
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Cloud Run service name."
  type        = string
  default     = "recon-mcp"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,47}[a-z0-9]$", var.service_name))
    error_message = "service_name must be 2 to 49 lowercase letters, digits, or hyphens and must start with a letter."
  }
}

variable "service_account_id" {
  description = "Account ID for the dedicated Cloud Run runtime identity."
  type        = string
  default     = "recon-mcp-runtime"
}

variable "container_image" {
  description = "Immutable Artifact Registry or other Cloud Run image reference, pinned by sha256 digest."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.container_image))
    error_message = "container_image must end in an immutable @sha256 digest."
  }
}

variable "access_mode" {
  description = "application-bearer supports remote AI services; google-iam supports Google identities and private clients."
  type        = string
  default     = "application-bearer"

  validation {
    condition     = contains(["application-bearer", "google-iam"], var.access_mode)
    error_message = "access_mode must be application-bearer or google-iam."
  }
}

variable "bearer_secret_id" {
  description = "Existing Secret Manager secret ID containing a random bearer token. Required only for application-bearer mode."
  type        = string
  default     = null
  nullable    = true
}

variable "bearer_secret_version" {
  description = "Numeric Secret Manager version used by the Cloud Run revision."
  type        = string
  default     = "1"

  validation {
    condition     = can(regex("^[1-9][0-9]*$", var.bearer_secret_version))
    error_message = "bearer_secret_version must be a numeric secret version, not latest."
  }
}

variable "invoker_members" {
  description = "Google IAM members granted roles/run.invoker in google-iam mode."
  type        = set(string)
  default     = []
}

variable "allowed_hosts" {
  description = "Optional exact Host header values enforced inside the container."
  type        = set(string)
  default     = []
}

variable "allowed_origins" {
  description = "Optional exact browser origins. Empty rejects every request that carries an Origin header."
  type        = set(string)
  default     = []
}

variable "min_instances" {
  description = "Minimum Cloud Run instances. Keep zero for the optional scale-to-zero path."
  type        = number
  default     = 0

  validation {
    condition     = var.min_instances >= 0 && floor(var.min_instances) == var.min_instances
    error_message = "min_instances must be a non-negative integer."
  }
}

variable "max_instances" {
  description = "Hard cost and fan-out bound for Cloud Run autoscaling."
  type        = number
  default     = 3

  validation {
    condition     = var.max_instances >= 1 && floor(var.max_instances) == var.max_instances
    error_message = "max_instances must be a positive integer."
  }
}

variable "container_concurrency" {
  description = "Maximum in-flight requests per instance. Start low for the I/O-heavy Python resolver."
  type        = number
  default     = 8

  validation {
    condition     = var.container_concurrency >= 1 && var.container_concurrency <= 1000
    error_message = "container_concurrency must be between 1 and 1000."
  }
}

variable "request_timeout_seconds" {
  description = "Cloud Run request timeout. This must exceed recon's bounded lookup timeout."
  type        = number
  default     = 180

  validation {
    condition     = var.request_timeout_seconds >= 130 && var.request_timeout_seconds <= 3600
    error_message = "request_timeout_seconds must be between 130 and 3600."
  }
}

variable "deletion_protection" {
  description = "Protect the Cloud Run service from accidental Terraform deletion."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Additional billing and ownership labels."
  type        = map(string)
  default     = {}
}
