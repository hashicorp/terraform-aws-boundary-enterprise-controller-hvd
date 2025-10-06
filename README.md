# Boundary Enterprise Controller HVD on AWS EC2

Terraform module aligned with HashiCorp Validated Designs (HVD) to deploy Boundary Enterprise Controller(s) on Amazon Web Services (AWS) using EC2 instances. This module is designed to work with the complimentary [Boundary Enterprise Worker HVD on AWS EC2](https://github.com/hashicorp/terraform-aws-boundary-enterprise-worker-hvd) module.

## Boundary Architecture

This diagram shows a Boundary deployment with one controller and two sets of Boundary Workers, one for ingress and another for egress. Please review [Boundary deployment customizations doc](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/docs/boundary-deployment-customizations.md) to understand different deployment settings for the Boundary deployment.

![Boundary on AWS](https://raw.githubusercontent.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/refs/heads/main/docs/images/boundary-diagram.png)

## Prerequisites

### General

- Terraform CLI `>= 1.9` installed on workstations.
- `Git` CLI and Visual Studio Code editor installed on workstations are strongly recommended.
- AWS account that Boundary will be hosted in with permissions to provision these [resources](#resources) via Terraform CLI.
- (Optional) AWS S3 bucket for [S3 Remote State backend](https://developer.hashicorp.com/terraform/language/settings/backends/s3) that will solely be used to stand up the Boundary infrastructure via Terraform CLI (Community Edition).

### Networking

- AWS VPC ID and the following subnets:
  - Load balancer subnet IDs (can be the same as EC2 subnets if desirable).
  - EC2 (controller) subnet IDs.
  - RDS (database) subnet IDs.
- (Optional) KMS VPC Endpoint configured within VPC.
- (Optional) AWS Route53 Hosted Zone for Boundary DNS record creation.
- Security Groups:
  - This module will create the necessary Security Groups and attach them to the applicable resources.
  - Ensure the [Boundary Network connectivity](https://developer.hashicorp.com/boundary/docs/install-boundary/architecture/system-requirements#network-connectivity) are met.

### Secrets Manager

- **Boundary license file** - raw contents of Boundary license file (`*.hclic`) (ex: `cat boundary.hclic`)
- **RDS (PostgreSQL) database password** - used to create AWS Aurora Database; randomly generate this yourself, fetched from within the module via data source.
- **Boundary TLS certificate** - file in PEM format, base64-encoded into a string, and stored as a plaintext secret.
- **Boundary TLS certificate private key** - file in PEM format, base64-encoded into a string, and stored as a plaintext secret.
- **TLS CA bundle** - file in PEM format, base64-encoded into a string, and stored as a plaintext secret.

>📝 Note: see the [Boundary cert rotation docs](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/docs/boundary-cert-rotation.md) for instructions on how to base64-encode the certificates with proper formatting.

### Compute

One of the following mechanisms for shell access to Boundary EC2 instances:

- EC2 SSH Key Pair.
- Ability to enable AWS SSM (this module supports this via a boolean input variable).

### KMS

This module supports creating the necessary KMS keys, Root, Recovery, Worker and BSR with the variables: `create_root_kms_key`, `create_recovery_kms_key`, `create_worker_kms_key` and if session recording is to be enabled, `create_bsr_kms_key`. If due to security policy KMS keys have to be provisioned outside this module, these variables can be set to `false` and the arn of each of the existing KMS keys can be provided with these variables, `root_kms_key_arn`, `recovery_kms_key_arn`, `worker_kms_key_arn` and if session recording is to be enabled `bsr_kms_key_arn`. Ensure that these already created KMS keys have a KMS policy that enables IAM authorization as this module will create IAM polices that grant access to these KMS keys.

## Usage

1. Create/configure/validate the applicable [prerequisites](#prerequisites).

1. Nested within the [examples](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/examples/) directory are subdirectories that contain ready-made Terraform configurations of example scenarios for how to call and deploy this module. To get started, choose an example scenario. If you are not sure which example scenario to start with, then we recommend starting with the [default](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/examples/default) example.

1. Copy all of the Terraform files from your example scenario of choice into a new destination directory to create your root Terraform configuration that will manage your Boundary deployment. If you are not sure where to create this new directory, it is common for us to see users create an `environments/` directory at the root of this repo, and then a subdirectory for each Boundary instance deployment, like so:

    ```sh
    .
    └── environments
        ├── production
        │   ├── backend.tf
        │   ├── main.tf
        │   ├── outputs.tf
        │   ├── terraform.tfvars
        │   └── variables.tf
        └── sandbox
            ├── backend.tf
            ├── main.tf
            ├── outputs.tf
            ├── terraform.tfvars
            └── variables.tf
    ```

    >📝 Note: in this example, the user will have two separate Boundary deployments; one for their `sandbox` environment, and one for their `production` environment. This is recommended, but not required.

1. (Optional) Uncomment and update the [S3 remote state backend](https://developer.hashicorp.com/terraform/language/settings/backends/s3) configuration provided in the `backend.tf` file with your own custom values. While this step is highly recommended, it is technically not required to use a remote backend config for your Boundary deployment.

1. Populate your own custom values into the `terraform.tfvars.example` file that was provided, and remove the `.example` file extension such that the file is now named `terraform.tfvars`.

1. Navigate to the directory of your newly created Terraform configuration for your Boundary Controller deployment, and run `terraform init`, `terraform plan`, and `terraform apply`.

1. After your `terraform apply` finishes successfully, you can monitor the installation progress by connecting to your Boundary EC2 instance shell via SSH or AWS SSM and observing the cloud-init (user_data) logs:

    Higher-level logs:

    ```sh
    tail -f /var/log/boundary-cloud-init.log
    ```

    Lower-level logs:

    ```sh
    journalctl -xu cloud-final -f
    ```

    >📝 Note: the `-f` argument is to follow the logs as they append in real-time, and is optional. You may remove the `-f` for a static view.

    The log files should display the following message after the cloud-init (user_data) script finishes successfully:

    ```sh
    [INFO] boundary_custom_data script finished successfully!
    ```

1. Once the cloud-init script finishes successfully, while still connected to the VM via SSH you can check the status of the boundary service:

    ```sh
    sudo systemctl status boundary
    ```

1. After the Boundary Controller is deployed the Boundary system will be partially initialized. To complete the initialization process and setup an initial auth method, username and password, please use the [terraform-boundary-bootstrap-hvd](https://registry.terraform.io/modules/hashicorp/bootstrap-hvd/boundary/latest) module

1. Use the [terraform-aws-boundary-worker-hvd](https://registry.terraform.io/modules/hashicorp/boundary-enterprise-worker-hvd/aws/latest) module to deploy ingress, egress, etc workers as needed.

## Docs

Below are links to docs pages related to deployment customizations and day 2 operations of your Boundary Controller instance.

- [Deployment Customizations](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/docs/boundary-deployment-customizations.md)
- [Upgrading Boundary version](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/docs/boundary-version-upgrades.md)
- [Rotating Boundary TLS/SSL certificates](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/docs/boundary-cert-rotation.md)
- [Updating/modifying Boundary configuration settings](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/docs/boundary-config-settings.md)
- [Authenticate to Boundary Cluster with Boundary CLI](https://github.com/hashicorp/terraform-aws-boundary-enterprise-controller-hvd/blob/main/docs/boundary-cli-auth.md)


## Troubleshooting

During deployment the output of the `user_data` script can be traced in `/var/log/cloud-init.log`, `/var/log/cloud-init-output.log` and `/var/log/boundary-cloud-init.log` due to `set -xeuo pipefail` in the default  `boundary_custom_data.sh.tpl`
For help debugging cloud init and user data scripts
- <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html#userdata-linux>
- <https://cloudinit.readthedocs.io/en/latest/howto/debugging.html#cloud-init-ran-but-didn-t-do-what-i-want-it-to>

## Module support

This open source software is maintained by the HashiCorp Technical Field Organization, independently of our enterprise products. While our Support Engineering team provides dedicated support for our enterprise offerings, this open source software is not included.

- For help using this open source software, please engage your account team.
- To report bugs/issues with this open source software, please open them directly against this code repository using the GitHub issues feature.

Please note that there is no official Service Level Agreement (SLA) for support of this software as a HashiCorp customer. This software falls under the definition of Community Software/Versions in your Agreement. We appreciate your understanding and collaboration in improving our open source projects.

<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.9 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 5.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 5.0 |

## Resources

| Name | Type |
|------|------|
| [aws_autoscaling_group.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group) | resource |
| [aws_db_parameter_group.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_parameter_group) | resource |
| [aws_db_subnet_group.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_subnet_group) | resource |
| [aws_iam_instance_profile.boundary_ec2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_instance_profile) | resource |
| [aws_iam_role.boundary_ec2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.boundary_ec2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.aws_ssm](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_alias.bsr](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_alias.recovery](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_alias.root](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_alias.worker](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.bsr](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_kms_key.recovery](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_kms_key.root](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_kms_key.worker](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_launch_template.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/launch_template) | resource |
| [aws_lb.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb) | resource |
| [aws_lb.cluster](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb) | resource |
| [aws_lb_listener.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener) | resource |
| [aws_lb_listener.cluster](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_listener) | resource |
| [aws_lb_target_group.api](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_lb_target_group.cluster](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group) | resource |
| [aws_rds_cluster.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster) | resource |
| [aws_rds_cluster_instance.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_instance) | resource |
| [aws_rds_cluster_parameter_group.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster_parameter_group) | resource |
| [aws_rds_global_cluster.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_global_cluster) | resource |
| [aws_route53_record.alias_record](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route53_record) | resource |
| [aws_s3_bucket.boundary_session_recording](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_public_access_block.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_security_group.api_lb_allow_egress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.api_lb_allow_ingress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.cluster_lb_allow_egress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.cluster_lb_allow_ingress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.ec2_allow_egress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.ec2_allow_ingress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.rds_allow_ingress](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group_rule.api_lb_allow_egress_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.api_lb_allow_ingress_https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.cluster_lb_allow_egress_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.cluster_lb_allow_ingress_cidr_9201](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_egress_all](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_egress_rds](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_ingress_9200_from_api_lb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_ingress_9201_cidr](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_ingress_9201_from_cluster_lb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_ingress_9201_sg](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_ingress_9203_from_api_lb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_ingress_9203_from_cluster_lb](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.ec2_allow_ingress_ssh](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.lb_allow_ingress_sg_9201](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_security_group_rule.rds_allow_ingress_from_ec2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group_rule) | resource |
| [aws_ami.amzn2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.centos](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.rhel](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_ami.ubuntu](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/ami) | data source |
| [aws_availability_zones.available](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/availability_zones) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.assume_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_bsr_kms_created](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_bsr_kms_provided](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_recovery_kms_created](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_recovery_kms_provided](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_root_kms_created](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_root_kms_provided](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_worker_kms_created](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.boundary_worker_kms_provided](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.combined](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.db](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.kms_cmk](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.license](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.rds_kms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.tls_ca](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.tls_cert](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.tls_privkey](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_kms_key.bsr](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_key) | data source |
| [aws_kms_key.recovery](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_key) | data source |
| [aws_kms_key.root](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_key) | data source |
| [aws_kms_key.worker](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/kms_key) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_route53_zone.boundary](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/route53_zone) | data source |
| [aws_secretsmanager_secret_version.boundary_database_password](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/secretsmanager_secret_version) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_api_lb_subnet_ids"></a> [api\_lb\_subnet\_ids](#input\_api\_lb\_subnet\_ids) | List of subnet IDs to use for the API load balancer. If the load balancer is external, then these should be public subnets. | `list(string)` | n/a | yes |
| <a name="input_boundary_database_password_secret_arn"></a> [boundary\_database\_password\_secret\_arn](#input\_boundary\_database\_password\_secret\_arn) | ARN of AWS Secrets Manager secret for the Boundary RDS Aurora (PostgreSQL) database password. | `string` | n/a | yes |
| <a name="input_boundary_fqdn"></a> [boundary\_fqdn](#input\_boundary\_fqdn) | Fully qualified domain name of boundary instance. This name should resolve to the load balancer IP address and will be what clients use to access boundary. | `string` | n/a | yes |
| <a name="input_boundary_tls_ca_bundle_secret_arn"></a> [boundary\_tls\_ca\_bundle\_secret\_arn](#input\_boundary\_tls\_ca\_bundle\_secret\_arn) | ARN of AWS Secrets Manager secret for private/custom TLS Certificate Authority (CA) bundle in PEM format. Secret must be stored as a base64-encoded string. | `string` | n/a | yes |
| <a name="input_cluster_lb_subnet_ids"></a> [cluster\_lb\_subnet\_ids](#input\_cluster\_lb\_subnet\_ids) | List of subnet IDs to use for the Cluster load balancer. If the load balancer is external, then these should be public subnets. | `list(string)` | n/a | yes |
| <a name="input_controller_subnet_ids"></a> [controller\_subnet\_ids](#input\_controller\_subnet\_ids) | List of subnet IDs to use for the EC2 instance. Private subnets is the best practice here. | `list(string)` | n/a | yes |
| <a name="input_friendly_name_prefix"></a> [friendly\_name\_prefix](#input\_friendly\_name\_prefix) | Friendly name prefix used for uniquely naming AWS resources. | `string` | n/a | yes |
| <a name="input_rds_subnet_ids"></a> [rds\_subnet\_ids](#input\_rds\_subnet\_ids) | List of subnet IDs to use for RDS database subnet group. Private subnets is the best practice here. | `list(string)` | n/a | yes |
| <a name="input_vpc_id"></a> [vpc\_id](#input\_vpc\_id) | ID of VPC where Boundary will be deployed. | `string` | n/a | yes |
| <a name="input_additional_package_names"></a> [additional\_package\_names](#input\_additional\_package\_names) | List of additional repository package names to install | `set(string)` | `[]` | no |
| <a name="input_api_lb_is_internal"></a> [api\_lb\_is\_internal](#input\_api\_lb\_is\_internal) | Boolean to create an internal (private) API load balancer. The `api_lb_subnet_ids` must be private subnets if this is set to `true`. | `bool` | `true` | no |
| <a name="input_asg_health_check_grace_period"></a> [asg\_health\_check\_grace\_period](#input\_asg\_health\_check\_grace\_period) | The amount of time to wait for a new Boundary EC2 instance to become healthy. If this threshold is breached, the ASG will terminate the instance and launch a new one. | `number` | `900` | no |
| <a name="input_asg_instance_count"></a> [asg\_instance\_count](#input\_asg\_instance\_count) | Desired number of Boundary EC2 instances to run in Autoscaling Group. Leave at `1` unless Active/Active is enabled. | `number` | `1` | no |
| <a name="input_asg_max_size"></a> [asg\_max\_size](#input\_asg\_max\_size) | Max number of Boundary EC2 instances to run in Autoscaling Group. | `number` | `3` | no |
| <a name="input_boundary_database_name"></a> [boundary\_database\_name](#input\_boundary\_database\_name) | Name of Boundary database to create within RDS global cluster. | `string` | `"boundary"` | no |
| <a name="input_boundary_database_parameters"></a> [boundary\_database\_parameters](#input\_boundary\_database\_parameters) | PostgreSQL server parameters for the connection URI. Used to configure the PostgreSQL connection. | `string` | `"sslmode=require"` | no |
| <a name="input_boundary_database_user"></a> [boundary\_database\_user](#input\_boundary\_database\_user) | Username for Boundary RDS database cluster. | `string` | `"boundary"` | no |
| <a name="input_boundary_license_reporting_opt_out"></a> [boundary\_license\_reporting\_opt\_out](#input\_boundary\_license\_reporting\_opt\_out) | Boolean to opt out of license reporting. | `bool` | `false` | no |
| <a name="input_boundary_license_secret_arn"></a> [boundary\_license\_secret\_arn](#input\_boundary\_license\_secret\_arn) | ARN of AWS Secrets Manager secret for Boundary license file. | `string` | `null` | no |
| <a name="input_boundary_session_recording_s3_kms_key_arn"></a> [boundary\_session\_recording\_s3\_kms\_key\_arn](#input\_boundary\_session\_recording\_s3\_kms\_key\_arn) | ARN of KMS customer managed key (CMK) to encrypt Boundary Session Recording Bucket with. | `string` | `null` | no |
| <a name="input_boundary_tls_cert_secret_arn"></a> [boundary\_tls\_cert\_secret\_arn](#input\_boundary\_tls\_cert\_secret\_arn) | ARN of AWS Secrets Manager secret for Boundary TLS certificate in PEM format. Secret must be stored as a base64-encoded string. | `string` | `null` | no |
| <a name="input_boundary_tls_disable"></a> [boundary\_tls\_disable](#input\_boundary\_tls\_disable) | Boolean to disable TLS for boundary. | `bool` | `false` | no |
| <a name="input_boundary_tls_privkey_secret_arn"></a> [boundary\_tls\_privkey\_secret\_arn](#input\_boundary\_tls\_privkey\_secret\_arn) | ARN of AWS Secrets Manager secret for Boundary TLS private key in PEM format. Secret must be stored as a base64-encoded string. | `string` | `null` | no |
| <a name="input_boundary_version"></a> [boundary\_version](#input\_boundary\_version) | Version of Boundary to install. | `string` | `"0.17.1+ent"` | no |
| <a name="input_bsr_kms_key_arn"></a> [bsr\_kms\_key\_arn](#input\_bsr\_kms\_key\_arn) | ARN of KMS key to use for Boundary bsr. | `string` | `null` | no |
| <a name="input_cidr_allow_egress_ec2_http"></a> [cidr\_allow\_egress\_ec2\_http](#input\_cidr\_allow\_egress\_ec2\_http) | List of destination CIDR ranges to allow TCP/80 egress from Boundary EC2 instances. | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_cidr_allow_egress_ec2_https"></a> [cidr\_allow\_egress\_ec2\_https](#input\_cidr\_allow\_egress\_ec2\_https) | List of destination CIDR ranges to allow TCP/443 egress from Boundary EC2 instances. | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_cidr_allow_ingress_boundary_443"></a> [cidr\_allow\_ingress\_boundary\_443](#input\_cidr\_allow\_ingress\_boundary\_443) | List of CIDR ranges to allow ingress traffic on port 443 to Load Balancer server. | `list(string)` | <pre>[<br/>  "0.0.0.0/0"<br/>]</pre> | no |
| <a name="input_cidr_allow_ingress_boundary_9201"></a> [cidr\_allow\_ingress\_boundary\_9201](#input\_cidr\_allow\_ingress\_boundary\_9201) | List of CIDR ranges to allow ingress traffic on port 9201 to Controllers. | `list(string)` | `null` | no |
| <a name="input_cidr_allow_ingress_ec2_ssh"></a> [cidr\_allow\_ingress\_ec2\_ssh](#input\_cidr\_allow\_ingress\_ec2\_ssh) | List of CIDR ranges to allow SSH ingress to Boundary EC2 instance (i.e. bastion IP, client/workstation IP, etc.). | `list(string)` | `[]` | no |
| <a name="input_common_tags"></a> [common\_tags](#input\_common\_tags) | Map of common tags for taggable AWS resources. | `map(string)` | `{}` | no |
| <a name="input_create_bsr_kms_key"></a> [create\_bsr\_kms\_key](#input\_create\_bsr\_kms\_key) | Boolean to create a KMS customer managed key (CMK) for Boundary Session Recording. | `bool` | `false` | no |
| <a name="input_create_lb"></a> [create\_lb](#input\_create\_lb) | Boolean to create an AWS Network Load Balancer for boundary. | `bool` | `true` | no |
| <a name="input_create_recovery_kms_key"></a> [create\_recovery\_kms\_key](#input\_create\_recovery\_kms\_key) | Boolean to create a KMS customer managed key (CMK) for Boundary Recovery. | `bool` | `true` | no |
| <a name="input_create_root_kms_key"></a> [create\_root\_kms\_key](#input\_create\_root\_kms\_key) | Boolean to create a KMS customer managed key (CMK) for Boundary Root. | `bool` | `true` | no |
| <a name="input_create_route53_boundary_dns_record"></a> [create\_route53\_boundary\_dns\_record](#input\_create\_route53\_boundary\_dns\_record) | Boolean to create Route53 Alias Record for `boundary_hostname` resolving to Load Balancer DNS name. If `true`, `route53_hosted_zone_boundary` is also required. | `bool` | `false` | no |
| <a name="input_create_worker_kms_key"></a> [create\_worker\_kms\_key](#input\_create\_worker\_kms\_key) | Boolean to create a KMS customer managed key (CMK) for Boundary Worker. | `bool` | `true` | no |
| <a name="input_custom_install_template"></a> [custom\_install\_template](#input\_custom\_install\_template) | Filename of a custom Install script template to use in place of the built-in user\_data script. The file must exist within a directory named './templates' in your current working directory. | `string` | `null` | no |
| <a name="input_ebs_iops"></a> [ebs\_iops](#input\_ebs\_iops) | The amount of IOPS to provision for a `gp3` volume. Must be at least `3000`. | `number` | `3000` | no |
| <a name="input_ebs_is_encrypted"></a> [ebs\_is\_encrypted](#input\_ebs\_is\_encrypted) | Boolean for encrypting the root block device of the Boundary EC2 instance(s). | `bool` | `false` | no |
| <a name="input_ebs_kms_key_arn"></a> [ebs\_kms\_key\_arn](#input\_ebs\_kms\_key\_arn) | ARN of KMS key to encrypt EC2 EBS volumes. | `string` | `null` | no |
| <a name="input_ebs_throughput"></a> [ebs\_throughput](#input\_ebs\_throughput) | The throughput to provision for a `gp3` volume in MB/s. Must be at least `125` MB/s. | `number` | `125` | no |
| <a name="input_ebs_volume_size"></a> [ebs\_volume\_size](#input\_ebs\_volume\_size) | The size (GB) of the root EBS volume for Boundary EC2 instances. Must be at least `50` GB. | `number` | `50` | no |
| <a name="input_ebs_volume_type"></a> [ebs\_volume\_type](#input\_ebs\_volume\_type) | EBS volume type for Boundary EC2 instances. | `string` | `"gp3"` | no |
| <a name="input_ec2_allow_ssm"></a> [ec2\_allow\_ssm](#input\_ec2\_allow\_ssm) | Boolean to attach the `AmazonSSMManagedInstanceCore` policy to the Boundary instance role, allowing the SSM agent (if present) to function. | `bool` | `false` | no |
| <a name="input_ec2_ami_id"></a> [ec2\_ami\_id](#input\_ec2\_ami\_id) | Custom AMI ID for Boundary EC2 Launch Template. If specified, value of `os_distro` must coincide with this custom AMI OS distro. | `string` | `null` | no |
| <a name="input_ec2_instance_size"></a> [ec2\_instance\_size](#input\_ec2\_instance\_size) | EC2 instance type for Boundary EC2 Launch Template. | `string` | `"m5.2xlarge"` | no |
| <a name="input_ec2_os_distro"></a> [ec2\_os\_distro](#input\_ec2\_os\_distro) | Linux OS distribution for Boundary EC2 instance. Choose from `amzn2`, `ubuntu`, `rhel`, `centos`. | `string` | `"ubuntu"` | no |
| <a name="input_ec2_ssh_key_pair"></a> [ec2\_ssh\_key\_pair](#input\_ec2\_ssh\_key\_pair) | Name of existing SSH key pair to attach to Boundary EC2 instance. | `string` | `""` | no |
| <a name="input_enable_session_recording"></a> [enable\_session\_recording](#input\_enable\_session\_recording) | Boolean to enable session recording. | `bool` | `false` | no |
| <a name="input_is_secondary_region"></a> [is\_secondary\_region](#input\_is\_secondary\_region) | Boolean indicating whether this Boundary instance deployment is in the primary or secondary (replica) region. | `bool` | `false` | no |
| <a name="input_kms_bsr_cmk_alias"></a> [kms\_bsr\_cmk\_alias](#input\_kms\_bsr\_cmk\_alias) | Alias for KMS customer managed key (CMK). | `string` | `"boundary-session-recording"` | no |
| <a name="input_kms_cmk_deletion_window"></a> [kms\_cmk\_deletion\_window](#input\_kms\_cmk\_deletion\_window) | Duration in days to destroy the key after it is deleted. Must be between 7 and 30 days. | `number` | `7` | no |
| <a name="input_kms_cmk_enable_key_rotation"></a> [kms\_cmk\_enable\_key\_rotation](#input\_kms\_cmk\_enable\_key\_rotation) | Boolean to enable key rotation for the KMS customer managed key (CMK). | `bool` | `false` | no |
| <a name="input_kms_endpoint"></a> [kms\_endpoint](#input\_kms\_endpoint) | AWS VPC endpoint for KMS service. | `string` | `""` | no |
| <a name="input_kms_recovery_cmk_alias"></a> [kms\_recovery\_cmk\_alias](#input\_kms\_recovery\_cmk\_alias) | Alias for KMS customer managed key (CMK). | `string` | `"boundary-recovery"` | no |
| <a name="input_kms_root_cmk_alias"></a> [kms\_root\_cmk\_alias](#input\_kms\_root\_cmk\_alias) | Alias for KMS customer managed key (CMK). | `string` | `"boundary-root"` | no |
| <a name="input_kms_worker_cmk_alias"></a> [kms\_worker\_cmk\_alias](#input\_kms\_worker\_cmk\_alias) | Alias for KMS customer managed key (CMK). | `string` | `"boundary-worker"` | no |
| <a name="input_rds_apply_immediately"></a> [rds\_apply\_immediately](#input\_rds\_apply\_immediately) | Boolean to apply changes immediately to RDS cluster instance. | `bool` | `true` | no |
| <a name="input_rds_aurora_engine_mode"></a> [rds\_aurora\_engine\_mode](#input\_rds\_aurora\_engine\_mode) | RDS Aurora database engine mode. | `string` | `"provisioned"` | no |
| <a name="input_rds_aurora_engine_version"></a> [rds\_aurora\_engine\_version](#input\_rds\_aurora\_engine\_version) | Engine version of RDS Aurora PostgreSQL. | `number` | `16.2` | no |
| <a name="input_rds_aurora_instance_class"></a> [rds\_aurora\_instance\_class](#input\_rds\_aurora\_instance\_class) | Instance class of Aurora PostgreSQL database. | `string` | `"db.r7g.xlarge"` | no |
| <a name="input_rds_aurora_replica_count"></a> [rds\_aurora\_replica\_count](#input\_rds\_aurora\_replica\_count) | Number of replica (reader) cluster instances to create within the RDS Aurora database cluster (within the same region). | `number` | `1` | no |
| <a name="input_rds_availability_zones"></a> [rds\_availability\_zones](#input\_rds\_availability\_zones) | List of AWS Availability Zones to spread Aurora database cluster instances across. Leave null and RDS will automatically assigns 3 AZs. | `list(string)` | `null` | no |
| <a name="input_rds_backup_retention_period"></a> [rds\_backup\_retention\_period](#input\_rds\_backup\_retention\_period) | The number of days to retain backups for. Must be between 0 and 35. Must be greater than 0 if the database cluster is used as a source of a read replica cluster. | `number` | `35` | no |
| <a name="input_rds_deletion_protection"></a> [rds\_deletion\_protection](#input\_rds\_deletion\_protection) | Boolean to enable deletion protection for RDS global cluster. | `bool` | `false` | no |
| <a name="input_rds_force_destroy"></a> [rds\_force\_destroy](#input\_rds\_force\_destroy) | Boolean to enable the removal of RDS database cluster members from RDS global cluster on destroy. | `bool` | `false` | no |
| <a name="input_rds_global_cluster_id"></a> [rds\_global\_cluster\_id](#input\_rds\_global\_cluster\_id) | ID of RDS global cluster. Only required when `is_secondary_region` is `true`. | `string` | `null` | no |
| <a name="input_rds_kms_key_arn"></a> [rds\_kms\_key\_arn](#input\_rds\_kms\_key\_arn) | ARN of KMS key to encrypt Boundary RDS cluster with. | `string` | `null` | no |
| <a name="input_rds_parameter_group_family"></a> [rds\_parameter\_group\_family](#input\_rds\_parameter\_group\_family) | Family of Aurora PostgreSQL DB Parameter Group. | `string` | `"aurora-postgresql16"` | no |
| <a name="input_rds_preferred_backup_window"></a> [rds\_preferred\_backup\_window](#input\_rds\_preferred\_backup\_window) | Daily time range (UTC) for RDS backup to occur. Must not overlap with `rds_preferred_maintenance_window`. | `string` | `"04:00-04:30"` | no |
| <a name="input_rds_preferred_maintenance_window"></a> [rds\_preferred\_maintenance\_window](#input\_rds\_preferred\_maintenance\_window) | Window (UTC) to perform RDS database maintenance. Must not overlap with `rds_preferred_backup_window`. | `string` | `"Sun:08:00-Sun:09:00"` | no |
| <a name="input_rds_replication_source_identifier"></a> [rds\_replication\_source\_identifier](#input\_rds\_replication\_source\_identifier) | ARN of a source DB cluster or DB instance if this DB cluster is to be created as a Read Replica. Intended to be used by Aurora Replica in Secondary region. | `string` | `null` | no |
| <a name="input_rds_skip_final_snapshot"></a> [rds\_skip\_final\_snapshot](#input\_rds\_skip\_final\_snapshot) | Boolean to enable RDS to take a final database snapshot before destroying. | `bool` | `false` | no |
| <a name="input_rds_source_region"></a> [rds\_source\_region](#input\_rds\_source\_region) | Source region for RDS cross-region replication. Only required when `is_secondary_region` is `true`. | `string` | `null` | no |
| <a name="input_rds_storage_encrypted"></a> [rds\_storage\_encrypted](#input\_rds\_storage\_encrypted) | Boolean to encrypt RDS storage. | `bool` | `false` | no |
| <a name="input_recovery_kms_key_arn"></a> [recovery\_kms\_key\_arn](#input\_recovery\_kms\_key\_arn) | ARN of KMS key to use for Boundary recovery. | `string` | `null` | no |
| <a name="input_root_kms_key_arn"></a> [root\_kms\_key\_arn](#input\_root\_kms\_key\_arn) | ARN of KMS key to use for Boundary Root. | `string` | `null` | no |
| <a name="input_route53_boundary_hosted_zone_is_private"></a> [route53\_boundary\_hosted\_zone\_is\_private](#input\_route53\_boundary\_hosted\_zone\_is\_private) | Boolean indicating if `route53_boundary_hosted_zone_name` is a private hosted zone. | `bool` | `false` | no |
| <a name="input_route53_boundary_hosted_zone_name"></a> [route53\_boundary\_hosted\_zone\_name](#input\_route53\_boundary\_hosted\_zone\_name) | Route53 Hosted Zone name to create `boundary_hostname` Alias record in. Required if `create_boundary_alias_record` is `true`. | `string` | `null` | no |
| <a name="input_sg_allow_ingress_boundary_9201"></a> [sg\_allow\_ingress\_boundary\_9201](#input\_sg\_allow\_ingress\_boundary\_9201) | List of Security Groups to allow ingress traffic on port 9201 to Controllers. | `list(string)` | `[]` | no |
| <a name="input_worker_kms_key_arn"></a> [worker\_kms\_key\_arn](#input\_worker\_kms\_key\_arn) | ARN of KMS key to use for Boundary worker. | `string` | `null` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_api_lb_dns_name"></a> [api\_lb\_dns\_name](#output\_api\_lb\_dns\_name) | DNS name of the Load Balancer for Boundary clients. |
| <a name="output_aurora_aws_rds_cluster_endpoint"></a> [aurora\_aws\_rds\_cluster\_endpoint](#output\_aurora\_aws\_rds\_cluster\_endpoint) | Aurora DB cluster instance endpoint. |
| <a name="output_aurora_rds_cluster_arn"></a> [aurora\_rds\_cluster\_arn](#output\_aurora\_rds\_cluster\_arn) | ARN of Aurora DB cluster. |
| <a name="output_aurora_rds_cluster_members"></a> [aurora\_rds\_cluster\_members](#output\_aurora\_rds\_cluster\_members) | List of instances that are part of this Aurora DB Cluster. |
| <a name="output_aurora_rds_global_cluster_id"></a> [aurora\_rds\_global\_cluster\_id](#output\_aurora\_rds\_global\_cluster\_id) | Aurora Global Database cluster identifier. |
| <a name="output_boundary_url"></a> [boundary\_url](#output\_boundary\_url) | URL to access Boundary application based on value of `boundary_fqdn` input. |
| <a name="output_bsr_s3_bucket_arn"></a> [bsr\_s3\_bucket\_arn](#output\_bsr\_s3\_bucket\_arn) | The arn of the S3 bucket for Boundary Session Recording. |
| <a name="output_cluster_lb_dns_name"></a> [cluster\_lb\_dns\_name](#output\_cluster\_lb\_dns\_name) | DNS name of the Load Balancer for Boundary Ingress Workers. |
| <a name="output_created_kms_bsr_arn"></a> [created\_kms\_bsr\_arn](#output\_created\_kms\_bsr\_arn) | The ARN of the created BSR KMS key |
| <a name="output_created_kms_recovery_arn"></a> [created\_kms\_recovery\_arn](#output\_created\_kms\_recovery\_arn) | The ARN of the created recovery KMS key |
| <a name="output_created_kms_recovery_id"></a> [created\_kms\_recovery\_id](#output\_created\_kms\_recovery\_id) | The ID of the created recovery KMS key |
| <a name="output_created_kms_root_arn"></a> [created\_kms\_root\_arn](#output\_created\_kms\_root\_arn) | The ARN of the created root KMS key |
| <a name="output_created_kms_worker_arn"></a> [created\_kms\_worker\_arn](#output\_created\_kms\_worker\_arn) | The ARN of the created worker KMS key |
| <a name="output_provided_kms_recovery_arn"></a> [provided\_kms\_recovery\_arn](#output\_provided\_kms\_recovery\_arn) | The ARN of the provided recovery  KMS key |
| <a name="output_provided_kms_recovery_id"></a> [provided\_kms\_recovery\_id](#output\_provided\_kms\_recovery\_id) | The ID of the provided recovery KMS key |
| <a name="output_provided_kms_root_arn"></a> [provided\_kms\_root\_arn](#output\_provided\_kms\_root\_arn) | The ARN of the provided root KMS key |
| <a name="output_provided_kms_worker_arn"></a> [provided\_kms\_worker\_arn](#output\_provided\_kms\_worker\_arn) | The ARN of the provided BSR KMS key |
| <a name="output_provided_kms_worker_id"></a> [provided\_kms\_worker\_id](#output\_provided\_kms\_worker\_id) | The ID of the provided worker KMS key |
<!-- END_TF_DOCS -->
