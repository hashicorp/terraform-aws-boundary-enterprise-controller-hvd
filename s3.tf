# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#------------------------------------------------------------------------------
# S3 bucket
#------------------------------------------------------------------------------
resource "aws_s3_bucket" "boundary_session_recording" {
  count = var.enable_session_recording ? 1 : 0

  bucket = "${var.friendly_name_prefix}-boundary-session-recording-${data.aws_region.current.name}"

  tags = merge(
    { "Name" = "${var.friendly_name_prefix}-boundary-session-recording-${data.aws_region.current.name}" },
    var.common_tags
  )
}

resource "aws_s3_bucket_public_access_block" "boundary" {
  count = var.enable_session_recording ? 1 : 0

  bucket = aws_s3_bucket.boundary_session_recording[0].id

  block_public_acls       = true
  block_public_policy     = true
  restrict_public_buckets = true
  ignore_public_acls      = true
}

resource "aws_s3_bucket_versioning" "boundary" {
  count = var.enable_session_recording ? 1 : 0

  bucket = aws_s3_bucket.boundary_session_recording[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "boundary" {
  count = var.enable_session_recording && var.boundary_session_recording_s3_kms_key_arn != null ? 1 : 0

  bucket = aws_s3_bucket.boundary_session_recording[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.boundary_session_recording_s3_kms_key_arn
    }
  }
}
