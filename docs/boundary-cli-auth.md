# Boundary CLI Auth

If access is needed during the Initial setup of Boundary, the CLI can be authenticated using the recovery KMS key.
Add the below to the main.tf in your example used for the deployment of the Boundary Controller(s)

```hcl
resource "local_file" "recovery_config" {
  filename        = "recovery.hcl"
  file_permission = "0600"
  content         = <<-EOF
    kms "awskms" {
      purpose    = "recovery"
      region     = "${var.region}"
      kms_key_id = "${module.boundary.created_kms_recovery_arn}"
    }
  EOF

}

output "next_steps" {
  value = <<-EOF
    export BOUNDARY_ADDR=${module.boundary.boundary_url}
    export BOUNDARY_RECOVERY_CONFIG=$${PWD}/recovery.hcl
  EOF
}
```

1. Run a `terraform apply`
2. Then set Environment variables for the boundary cluster address and to use the recovery config file that has been generated in the Terraform output as `next_steps`
3. If a private CA is used, ensure the CA is installed locally.
4. Using the Boundary CLI try `boundary scopes list` That will then authenticate to the Boundary Cluster and CLI commands can be run.  
