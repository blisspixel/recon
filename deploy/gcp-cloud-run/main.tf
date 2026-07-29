locals {
  application_bearer = var.access_mode == "application-bearer"
  secret_id          = coalesce(var.bearer_secret_id, "not-configured")
}

resource "google_project_service" "required" {
  for_each = toset([
    "iam.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "recon remote MCP runtime"

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_iam_member" "bearer" {
  count = local.application_bearer ? 1 : 0

  project   = var.project_id
  secret_id = local.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"

  depends_on = [google_project_service.required]
}

resource "google_cloud_run_v2_service" "recon" {
  project             = var.project_id
  name                = var.service_name
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = var.deletion_protection
  labels = merge(
    {
      application = "recon"
      managed-by  = "terraform"
      surface     = "optional-remote-mcp"
    },
    var.labels,
  )

  template {
    service_account                  = google_service_account.runtime.email
    timeout                          = "${var.request_timeout_seconds}s"
    max_instance_request_concurrency = var.container_concurrency

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    containers {
      image = var.container_image

      ports {
        name           = "http1"
        container_port = 8080
      }

      env {
        name  = "RECON_REMOTE_AUTH_MODE"
        value = local.application_bearer ? "static-bearer" : "trusted-platform"
      }

      env {
        name  = "RECON_REMOTE_ALLOWED_HOSTS"
        value = join(",", sort(tolist(var.allowed_hosts)))
      }

      env {
        name  = "RECON_REMOTE_ALLOWED_ORIGINS"
        value = join(",", sort(tolist(var.allowed_origins)))
      }

      dynamic "env" {
        for_each = local.application_bearer ? [1] : []
        content {
          name = "RECON_REMOTE_BEARER_TOKEN"
          value_source {
            secret_key_ref {
              secret  = "projects/${var.project_id}/secrets/${local.secret_id}"
              version = var.bearer_secret_version
            }
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      startup_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 2
        period_seconds        = 2
        failure_threshold     = 30

        http_get {
          path = "/health"
          port = 8080
        }
      }

      liveness_probe {
        initial_delay_seconds = 0
        timeout_seconds       = 2
        period_seconds        = 30
        failure_threshold     = 3

        http_get {
          path = "/health"
          port = 8080
        }
      }
    }
  }

  lifecycle {
    precondition {
      condition     = !local.application_bearer || var.bearer_secret_id != null
      error_message = "bearer_secret_id is required in application-bearer mode."
    }

    precondition {
      condition     = var.max_instances >= var.min_instances
      error_message = "max_instances must be greater than or equal to min_instances."
    }
  }

  depends_on = [
    google_project_service.required,
    google_secret_manager_secret_iam_member.bearer,
  ]
}

resource "google_cloud_run_v2_service_iam_member" "public" {
  count = local.application_bearer ? 1 : 0

  project  = google_cloud_run_v2_service.recon.project
  location = google_cloud_run_v2_service.recon.location
  name     = google_cloud_run_v2_service.recon.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

resource "google_cloud_run_v2_service_iam_member" "named_invokers" {
  for_each = local.application_bearer ? toset([]) : var.invoker_members

  project  = google_cloud_run_v2_service.recon.project
  location = google_cloud_run_v2_service.recon.location
  name     = google_cloud_run_v2_service.recon.name
  role     = "roles/run.invoker"
  member   = each.value
}
