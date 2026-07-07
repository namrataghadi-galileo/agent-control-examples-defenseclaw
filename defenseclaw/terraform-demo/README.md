# Provider-free Terraform fixture

This fixture exists only so a coding agent can inspect a realistic `.tf` file
before the steering demo. It uses Terraform's built-in `terraform_data`
resource and declares no external provider, backend, credentials, or cloud
resource.

The protected launcher resolves `terraform` to the repository's no-execution
simulator. Neither `plan` nor `validate` invokes a real Terraform binary.
