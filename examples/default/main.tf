# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.47.0"
    }
  }
}

provider "aws" {
  region = var.region # change to your desired region
}

module "boundary" {
  source = "../.."

  # Common
  friendly_name_prefix = var.friendly_name_prefix
  common_tags          = var.common_tags

  # Pre-requisites
  boundary_license_secret_arn           = var.boundary_license_secret_arn
  boundary_tls_cert_secret_arn          = var.boundary_tls_cert_secret_arn
  boundary_tls_privkey_secret_arn       = var.boundary_tls_privkey_secret_arn
  boundary_tls_ca_bundle_secret_arn     = var.boundary_tls_ca_bundle_secret_arn
  boundary_database_password_secret_arn = var.boundary_database_password_secret_arn

  # Boundary configuration settings
  boundary_fqdn            = var.boundary_fqdn
  enable_session_recording = var.enable_session_recording

  # Networking
  vpc_id                           = var.vpc_id
  api_lb_subnet_ids                = var.api_lb_subnet_ids
  api_lb_is_internal               = var.api_lb_is_internal
  cluster_lb_subnet_ids            = var.cluster_lb_subnet_ids
  controller_subnet_ids            = var.controller_subnet_ids
  rds_subnet_ids                   = var.rds_subnet_ids
  cidr_allow_ingress_boundary_443  = var.cidr_allow_ingress_boundary_443
  cidr_allow_ingress_boundary_9201 = var.cidr_allow_ingress_boundary_9201
  sg_allow_ingress_boundary_9201   = var.sg_allow_ingress_boundary_9201
  cidr_allow_ingress_ec2_ssh       = var.cidr_allow_ingress_ec2_ssh

  # DNS (optional)
  create_route53_boundary_dns_record = var.create_route53_boundary_dns_record
  route53_boundary_hosted_zone_name  = var.route53_boundary_hosted_zone_name

  # Compute
  ec2_os_distro      = var.ec2_os_distro
  ec2_ssh_key_pair   = var.ec2_ssh_key_pair
  asg_instance_count = var.asg_instance_count

  # Database
  rds_skip_final_snapshot = var.rds_skip_final_snapshot

  #IAM
  ec2_allow_ssm = var.ec2_allow_ssm

  #KMS
  create_bsr_kms_key = var.create_bsr_kms_key
}
