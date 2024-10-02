# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#------------------------------------------------------------------------------
# Boundary URLs
#------------------------------------------------------------------------------
output "boundary_url" {
  value       = module.boundary.boundary_url
  description = "URL to access Boundary application based on value of `boundary_fqdn` input."
}

output "boundary_api_lb_dns_name" {
  value       = module.boundary.api_lb_dns_name
  description = "DNS name of the Load Balancer for Boundary clients."
}

output "boundary_cluster_lb_dns_name" {
  value       = module.boundary.cluster_lb_dns_name
  description = "DNS name of the Load Balancer for Boundary Ingress Workers."
}

#------------------------------------------------------------------------------
# KMS
#------------------------------------------------------------------------------
output "created_kms_root_arn" {
  value       = module.boundary.created_kms_root_arn
  description = "The ARN of the created root KMS key"
}

output "created_kms_recovery_arn" {
  value       = module.boundary.created_kms_recovery_arn
  description = "The ARN of the created recovery KMS key"
}

output "created_kms_recovery_id" {
  value       = module.boundary.created_kms_recovery_id
  description = "The ID of the created recovery KMS key"
}

output "created_kms_worker_arn" {
  value       = module.boundary.created_kms_worker_arn
  description = "The ARN of the created worker KMS key"
}

output "created_kms_bsr_arn" {
  value       = module.boundary.created_kms_bsr_arn
  description = "The ARN of the created worker KMS key"
}

output "provided_kms_root_arn" {
  value       = module.boundary.provided_kms_root_arn
  description = "The ARN of the provided root KMS key"
}

output "provided_kms_recovery_arn" {
  value       = module.boundary.provided_kms_recovery_arn
  description = "The ARN of the provided recovery KMS key"
}

output "provided_kms_recovery_id" {
  value       = module.boundary.provided_kms_recovery_id
  description = "The ID of the provided recovery KMS key"
}

output "provided_kms_worker_arn" {
  value       = module.boundary.provided_kms_worker_arn
  description = "The ARN of the provided worker KMS key"
}

#------------------------------------------------------------------------------
# S3
#------------------------------------------------------------------------------
output "bsr_s3_bucket_arn" {
  value       = module.boundary.bsr_s3_bucket_arn
  description = "The arn of the S3 bucket for Boundary Session Recording."
}
