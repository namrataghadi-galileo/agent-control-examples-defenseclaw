terraform {
  required_version = ">= 1.5.0"
}

variable "ticket" {
  description = "Placeholder change-ticket identifier for the steering demo."
  type        = string
  default     = "INFRA-204"
}

resource "terraform_data" "review" {
  input = {
    ticket = var.ticket
    mode   = "simulation-only"
  }
}

output "review_summary" {
  value = terraform_data.review.output
}
