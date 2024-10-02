# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#------------------------------------------------------------------------------
# Common
#------------------------------------------------------------------------------
variable "friendly_name_prefix" {
  type        = string
  description = "Friendly name prefix used for uniquely naming AWS resources."
  validation {
    condition     = length(var.friendly_name_prefix) > 0 && length(var.friendly_name_prefix) < 17
    error_message = "Friendly name prefix must be between 1 and 16 characters."
  }
}

variable "common_tags" {
  type        = map(string)
  description = "Map of common tags for taggable AWS resources."
  default     = {}
}

variable "is_secondary_region" {
  type        = bool
  description = "Boolean indicating whether this Boundary instance deployment is in the primary or secondary (replica) region."
  default     = false
}

#------------------------------------------------------------------------------
# Prereqs
#------------------------------------------------------------------------------
variable "boundary_license_secret_arn" {
  type        = string
  description = "ARN of AWS Secrets Manager secret for Boundary license file."
  default     = null
}

variable "boundary_tls_cert_secret_arn" {
  type        = string
  description = "ARN of AWS Secrets Manager secret for Boundary TLS certificate in PEM format. Secret must be stored as a base64-encoded string."
  default     = null
}

variable "boundary_tls_privkey_secret_arn" {
  type        = string
  description = "ARN of AWS Secrets Manager secret for Boundary TLS private key in PEM format. Secret must be stored as a base64-encoded string."
  default     = null
}

variable "boundary_tls_ca_bundle_secret_arn" {
  type        = string
  description = "ARN of AWS Secrets Manager secret for private/custom TLS Certificate Authority (CA) bundle in PEM format. Secret must be stored as a base64-encoded string."
  nullable    = true
}

variable "additional_package_names" {
  type        = set(string)
  description = "List of additional repository package names to install"
  default     = []
}

#------------------------------------------------------------------------------
# Boundary Configuration Settings
#------------------------------------------------------------------------------
variable "boundary_fqdn" {
  type        = string
  description = "Fully qualified domain name of boundary instance. This name should resolve to the load balancer IP address and will be what clients use to access boundary."
}

variable "boundary_license_reporting_opt_out" {
  type        = bool
  description = "Boolean to opt out of license reporting."
  default     = false
}

variable "boundary_tls_disable" {
  type        = bool
  description = "Boolean to disable TLS for boundary."
  default     = false
}

variable "boundary_version" {
  type        = string
  description = "Version of Boundary to install."
  default     = "0.17.1+ent"
  validation {
    condition     = can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+\\+ent$", var.boundary_version))
    error_message = "Value must be in the format 'X.Y.Z+ent'."
  }
}

variable "enable_session_recording" {
  type        = bool
  description = "Boolean to enable session recording."
  default     = false
  validation {
    condition     = var.enable_session_recording == true ? (var.create_bsr_kms_key || var.bsr_kms_key_arn != null) : true
    error_message = "Session recording requires the BSR KMS Key to be created or an existing bsr KMS Key to be provided."
  }
}

#------------------------------------------------------------------------------
# Networking
#------------------------------------------------------------------------------
variable "vpc_id" {
  type        = string
  description = "ID of VPC where Boundary will be deployed."
}

variable "api_lb_subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs to use for the API load balancer. If the load balancer is external, then these should be public subnets."
}

variable "cluster_lb_subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs to use for the Cluster load balancer. If the load balancer is external, then these should be public subnets."
}

variable "controller_subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs to use for the EC2 instance. Private subnets is the best practice here."
}

variable "rds_subnet_ids" {
  type        = list(string)
  description = "List of subnet IDs to use for RDS database subnet group. Private subnets is the best practice here."
}

variable "create_lb" {
  type        = bool
  description = "Boolean to create an AWS Network Load Balancer for boundary."
  default     = true
}

variable "api_lb_is_internal" {
  type        = bool
  description = "Boolean to create an internal (private) API load balancer. The `api_lb_subnet_ids` must be private subnets if this is set to `true`."
  default     = true
}

variable "create_route53_boundary_dns_record" {
  type        = bool
  description = "Boolean to create Route53 Alias Record for `boundary_hostname` resolving to Load Balancer DNS name. If `true`, `route53_hosted_zone_boundary` is also required."
  default     = false
}

variable "route53_boundary_hosted_zone_name" {
  type        = string
  description = "Route53 Hosted Zone name to create `boundary_hostname` Alias record in. Required if `create_boundary_alias_record` is `true`."
  default     = null
}

variable "route53_boundary_hosted_zone_is_private" {
  type        = bool
  description = "Boolean indicating if `route53_boundary_hosted_zone_name` is a private hosted zone."
  default     = false
}

variable "cidr_allow_ingress_boundary_443" {
  type        = list(string)
  description = "List of CIDR ranges to allow ingress traffic on port 443 to Load Balancer server."
  default     = ["0.0.0.0/0"]
}

variable "cidr_allow_ingress_boundary_9201" {
  type        = list(string)
  description = "List of CIDR ranges to allow ingress traffic on port 9201 to Controllers."
  default     = null
}

variable "sg_allow_ingress_boundary_9201" {
  type        = list(string)
  description = "List of Security Groups to allow ingress traffic on port 9201 to Controllers."
  default     = []
}

variable "cidr_allow_ingress_ec2_ssh" {
  type        = list(string)
  description = "List of CIDR ranges to allow SSH ingress to Boundary EC2 instance (i.e. bastion IP, client/workstation IP, etc.)."
  default     = []
}

variable "cidr_allow_egress_ec2_http" {
  type        = list(string)
  description = "List of destination CIDR ranges to allow TCP/80 egress from Boundary EC2 instances."
  default     = ["0.0.0.0/0"]
}

variable "cidr_allow_egress_ec2_https" {
  type        = list(string)
  description = "List of destination CIDR ranges to allow TCP/443 egress from Boundary EC2 instances."
  default     = ["0.0.0.0/0"]
}

#------------------------------------------------------------------------------
# Compute
#------------------------------------------------------------------------------
variable "ec2_os_distro" {
  type        = string
  description = "Linux OS distribution for Boundary EC2 instance. Choose from `amzn2`, `ubuntu`, `rhel`, `centos`."
  default     = "ubuntu"

  validation {
    condition     = contains(["amzn2", "ubuntu", "rhel", "centos"], var.ec2_os_distro)
    error_message = "Supported values are `amzn2`, `ubuntu`, `rhel` or `centos`."
  }
}

variable "asg_instance_count" {
  type        = number
  description = "Desired number of Boundary EC2 instances to run in Autoscaling Group. Leave at `1` unless Active/Active is enabled."
  default     = 1
}

variable "asg_max_size" {
  type        = number
  description = "Max number of Boundary EC2 instances to run in Autoscaling Group."
  default     = 3
}

variable "asg_health_check_grace_period" {
  type        = number
  description = "The amount of time to wait for a new Boundary EC2 instance to become healthy. If this threshold is breached, the ASG will terminate the instance and launch a new one."
  default     = 900
}

variable "ec2_ami_id" {
  type        = string
  description = "Custom AMI ID for Boundary EC2 Launch Template. If specified, value of `os_distro` must coincide with this custom AMI OS distro."
  default     = null

  validation {
    condition     = try((length(var.ec2_ami_id) > 4 && substr(var.ec2_ami_id, 0, 4) == "ami-"), var.ec2_ami_id == null)
    error_message = "Value must start with \"ami-\"."
  }
}

variable "ec2_instance_size" {
  type        = string
  description = "EC2 instance type for Boundary EC2 Launch Template."
  default     = "m5.2xlarge"
}

variable "ec2_ssh_key_pair" {
  type        = string
  description = "Name of existing SSH key pair to attach to Boundary EC2 instance."
  default     = ""
}

variable "ec2_allow_ssm" {
  type        = bool
  description = "Boolean to attach the `AmazonSSMManagedInstanceCore` policy to the Boundary instance role, allowing the SSM agent (if present) to function."
  default     = false
}

variable "ebs_is_encrypted" {
  type        = bool
  description = "Boolean for encrypting the root block device of the Boundary EC2 instance(s)."
  default     = false
}

variable "ebs_kms_key_arn" {
  type        = string
  description = "ARN of KMS key to encrypt EC2 EBS volumes."
  default     = null
}

variable "ebs_volume_type" {
  type        = string
  description = "EBS volume type for Boundary EC2 instances."
  default     = "gp3"

  validation {
    condition     = var.ebs_volume_type == "gp3" || var.ebs_volume_type == "gp2"
    error_message = "Supported values are 'gp3' and 'gp2'."
  }
}

variable "ebs_volume_size" {
  type        = number
  description = "The size (GB) of the root EBS volume for Boundary EC2 instances. Must be at least `50` GB."
  default     = 50

  validation {
    condition     = var.ebs_volume_size >= 50 && var.ebs_volume_size <= 16000
    error_message = "The ebs volume must be greater `50` GB and lower than `16000` GB (16TB)."
  }
}

variable "ebs_throughput" {
  type        = number
  description = "The throughput to provision for a `gp3` volume in MB/s. Must be at least `125` MB/s."
  default     = 125

  validation {
    condition = (
      var.ebs_throughput >= 125 &&
      var.ebs_throughput <= 1000
    )
    error_message = "The throughput must be at least `125` MB/s and lower than `1000` MB/s."
  }
}

variable "ebs_iops" {
  type        = number
  description = "The amount of IOPS to provision for a `gp3` volume. Must be at least `3000`."
  default     = 3000

  validation {
    condition = (
      var.ebs_iops >= 3000 &&
      var.ebs_iops <= 16000
    )
    error_message = "The IOPS must be at least `3000` GB and lower than `16000` (16TB)."
  }
}

#------------------------------------------------------------------------------
# RDS Aurora PostgreSQL
#------------------------------------------------------------------------------
variable "boundary_database_password_secret_arn" {
  type        = string
  description = "ARN of AWS Secrets Manager secret for the Boundary RDS Aurora (PostgreSQL) database password."
}

variable "boundary_database_name" {
  type        = string
  description = "Name of Boundary database to create within RDS global cluster."
  default     = "boundary"
}

variable "rds_availability_zones" {
  type        = list(string)
  description = "List of AWS Availability Zones to spread Aurora database cluster instances across. Leave null and RDS will automatically assigns 3 AZs."
  default     = null

  validation {
    condition     = try(length(var.rds_availability_zones) <= 3, var.rds_availability_zones == null)
    error_message = "A maximum of three Availability Zones can be specified."
  }
}

variable "rds_deletion_protection" {
  type        = bool
  description = "Boolean to enable deletion protection for RDS global cluster."
  default     = false
}

variable "rds_aurora_engine_version" {
  type        = number
  description = "Engine version of RDS Aurora PostgreSQL."
  default     = 16.2
}

variable "rds_force_destroy" {
  type        = bool
  description = "Boolean to enable the removal of RDS database cluster members from RDS global cluster on destroy."
  default     = false
}

variable "rds_storage_encrypted" {
  type        = bool
  description = "Boolean to encrypt RDS storage."
  default     = false
}

variable "rds_global_cluster_id" {
  type        = string
  description = "ID of RDS global cluster. Only required when `is_secondary_region` is `true`."
  default     = null
}

variable "rds_aurora_engine_mode" {
  type        = string
  description = "RDS Aurora database engine mode."
  default     = "provisioned"
}

variable "boundary_database_user" {
  type        = string
  description = "Username for Boundary RDS database cluster."
  default     = "boundary"
}

variable "boundary_database_parameters" {
  type        = string
  description = "PostgreSQL server parameters for the connection URI. Used to configure the PostgreSQL connection."
  default     = "sslmode=require"
}

variable "rds_kms_key_arn" {
  type        = string
  description = "ARN of KMS key to encrypt Boundary RDS cluster with."
  default     = null
}

variable "rds_replication_source_identifier" {
  type        = string
  description = "ARN of a source DB cluster or DB instance if this DB cluster is to be created as a Read Replica. Intended to be used by Aurora Replica in Secondary region."
  default     = null
}

variable "rds_source_region" {
  type        = string
  description = "Source region for RDS cross-region replication. Only required when `is_secondary_region` is `true`."
  default     = null
}

variable "rds_backup_retention_period" {
  type        = number
  description = "The number of days to retain backups for. Must be between 0 and 35. Must be greater than 0 if the database cluster is used as a source of a read replica cluster."
  default     = 35

  validation {
    condition     = var.rds_backup_retention_period >= 0 && var.rds_backup_retention_period <= 35
    error_message = "Value must be between 0 and 35."
  }
}

variable "rds_preferred_backup_window" {
  type        = string
  description = "Daily time range (UTC) for RDS backup to occur. Must not overlap with `rds_preferred_maintenance_window`."
  default     = "04:00-04:30"

  validation {
    condition     = can(regex("^([01]?[0-9]|2[0-3]):[0-5][0-9]-([01]?[0-9]|2[0-3]):[0-5][0-9]$", var.rds_preferred_backup_window))
    error_message = "Value must be in the format 'HH:MM-HH:MM'."
  }
}

variable "rds_preferred_maintenance_window" {
  type        = string
  description = "Window (UTC) to perform RDS database maintenance. Must not overlap with `rds_preferred_backup_window`."
  default     = "Sun:08:00-Sun:09:00"

  validation {
    condition     = can(regex("^(Mon|Tue|Wed|Thu|Fri|Sat|Sun):([01]?[0-9]|2[0-3]):[0-5][0-9]-(Mon|Tue|Wed|Thu|Fri|Sat|Sun):([01]?[0-9]|2[0-3]):[0-5][0-9]$", var.rds_preferred_maintenance_window))
    error_message = "Value must be in the format 'Day:HH:MM-Day:HH:MM'."
  }
}

variable "rds_skip_final_snapshot" {
  type        = bool
  description = "Boolean to enable RDS to take a final database snapshot before destroying."
  default     = false
}

variable "rds_aurora_instance_class" {
  type        = string
  description = "Instance class of Aurora PostgreSQL database."
  default     = "db.r7g.xlarge"
}

variable "rds_apply_immediately" {
  type        = bool
  description = "Boolean to apply changes immediately to RDS cluster instance."
  default     = true
}

variable "rds_parameter_group_family" {
  type        = string
  description = "Family of Aurora PostgreSQL DB Parameter Group."
  default     = "aurora-postgresql16"
}

variable "rds_aurora_replica_count" {
  type        = number
  description = "Number of replica (reader) cluster instances to create within the RDS Aurora database cluster (within the same region)."
  default     = 1
}

#------------------------------------------------------------------------------
# KMS
#------------------------------------------------------------------------------
variable "create_root_kms_key" {
  type        = bool
  description = "Boolean to create a KMS customer managed key (CMK) for Boundary Root."
  default     = true
}

variable "create_recovery_kms_key" {
  type        = bool
  description = "Boolean to create a KMS customer managed key (CMK) for Boundary Recovery."
  default     = true
}

variable "create_worker_kms_key" {
  type        = bool
  description = "Boolean to create a KMS customer managed key (CMK) for Boundary Worker."
  default     = true
}

variable "create_bsr_kms_key" {
  type        = bool
  description = "Boolean to create a KMS customer managed key (CMK) for Boundary Session Recording."
  default     = false
}

variable "root_kms_key_arn" {
  type        = string
  description = "ARN of KMS key to use for Boundary Root."
  default     = null
  validation {
    condition     = var.create_root_kms_key == false ? var.root_kms_key_arn != null : true
    error_message = "Root KMS key must be provided if `create_root_kms_key` is set to `false`."
  }
}

variable "recovery_kms_key_arn" {
  type        = string
  description = "ARN of KMS key to use for Boundary recovery."
  default     = null
  validation {
    condition     = var.create_recovery_kms_key == false ? var.recovery_kms_key_arn != null : true
    error_message = "Recovery KMS key must be provided if `create_recovery_kms_key` is set to `false`."
  }
}

variable "worker_kms_key_arn" {
  type        = string
  description = "ARN of KMS key to use for Boundary worker."
  default     = null
  validation {
    condition     = var.create_worker_kms_key == false ? var.worker_kms_key_arn != null : true
    error_message = "Worker KMS key must be provided if `create_worker_kms_key` is set to `false`."
  }
}

variable "bsr_kms_key_arn" {
  type        = string
  description = "ARN of KMS key to use for Boundary bsr."
  default     = null
}

variable "kms_root_cmk_alias" {
  type        = string
  description = "Alias for KMS customer managed key (CMK)."
  default     = "boundary-root"
}

variable "kms_recovery_cmk_alias" {
  type        = string
  description = "Alias for KMS customer managed key (CMK)."
  default     = "boundary-recovery"
}

variable "kms_worker_cmk_alias" {
  type        = string
  description = "Alias for KMS customer managed key (CMK)."
  default     = "boundary-worker"
}

variable "kms_bsr_cmk_alias" {
  type        = string
  description = "Alias for KMS customer managed key (CMK)."
  default     = "boundary-session-recording"
}

variable "kms_cmk_deletion_window" {
  type        = number
  description = "Duration in days to destroy the key after it is deleted. Must be between 7 and 30 days."
  default     = 7
}

variable "kms_cmk_enable_key_rotation" {
  type        = bool
  description = "Boolean to enable key rotation for the KMS customer managed key (CMK)."
  default     = false
}

variable "kms_endpoint" {
  type        = string
  description = "AWS VPC endpoint for KMS service."
  default     = ""
}

#------------------------------------------------------------------------------
# S3
#------------------------------------------------------------------------------
variable "boundary_session_recording_s3_kms_key_arn" {
  type        = string
  description = "ARN of KMS customer managed key (CMK) to encrypt Boundary Session Recording Bucket with."
  default     = null
}
