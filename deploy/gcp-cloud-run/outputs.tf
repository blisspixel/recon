output "service_url" {
  description = "Cloud Run service base URL."
  value       = google_cloud_run_v2_service.recon.uri
}

output "mcp_url" {
  description = "Remote Streamable HTTP MCP endpoint."
  value       = "${google_cloud_run_v2_service.recon.uri}/mcp"
}

output "access_mode" {
  description = "Authentication boundary selected for this deployment."
  value       = var.access_mode
}

output "runtime_service_account" {
  description = "Least-privilege identity used by the Cloud Run revision."
  value       = google_service_account.runtime.email
}
