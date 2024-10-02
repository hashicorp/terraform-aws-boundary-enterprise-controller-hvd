# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "aws_iam_policy_document" "kms_cmk" {

  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
}

#------------------------------------------------------------------------------
# Existing KMS keys
#------------------------------------------------------------------------------
data "aws_kms_key" "root" {
  count = var.root_kms_key_arn != null ? 1 : 0

  key_id = var.root_kms_key_arn
}

data "aws_kms_key" "recovery" {
  count = var.recovery_kms_key_arn != null ? 1 : 0

  key_id = var.recovery_kms_key_arn
}

data "aws_kms_key" "worker" {
  count = var.worker_kms_key_arn != null ? 1 : 0

  key_id = var.worker_kms_key_arn
}

data "aws_kms_key" "bsr" {
  count = var.bsr_kms_key_arn != null && var.enable_session_recording == true ? 1 : 0

  key_id = var.bsr_kms_key_arn
}

#------------------------------------------------------------------------------
# KMS Customer Managed Key (CMK) Root
#------------------------------------------------------------------------------
resource "aws_kms_key" "root" {
  count = var.create_root_kms_key ? 1 : 0

  description             = "AWS KMS customer-managed key (CMK) for Boundary Root"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_cmk_deletion_window
  is_enabled              = true
  enable_key_rotation     = var.kms_cmk_enable_key_rotation
  policy                  = data.aws_iam_policy_document.kms_cmk.json

  tags = merge(
    { Name = "${var.friendly_name_prefix}-boundary-kms-root-cmk" },
    var.common_tags
  )
}

resource "aws_kms_alias" "root" {
  count = var.kms_root_cmk_alias != null ? 1 : 0

  name          = "alias/${var.kms_root_cmk_alias}"
  target_key_id = aws_kms_key.root[0].id
}

#------------------------------------------------------------------------------
# KMS Customer Managed Key (CMK) Recovery
#------------------------------------------------------------------------------
resource "aws_kms_key" "recovery" {
  count = var.create_recovery_kms_key ? 1 : 0

  description             = "AWS KMS customer-managed key (CMK) for Boundary recovery"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_cmk_deletion_window
  is_enabled              = true
  enable_key_rotation     = var.kms_cmk_enable_key_rotation
  policy                  = data.aws_iam_policy_document.kms_cmk.json

  tags = merge(
    { Name = "${var.friendly_name_prefix}-boundary-kms-recovery-cmk" },
    var.common_tags
  )
}

resource "aws_kms_alias" "recovery" {
  count = var.kms_recovery_cmk_alias != null ? 1 : 0

  name          = "alias/${var.kms_recovery_cmk_alias}"
  target_key_id = aws_kms_key.recovery[0].id
}

#------------------------------------------------------------------------------
# KMS Customer Managed Key (CMK) Worker
#------------------------------------------------------------------------------
resource "aws_kms_key" "worker" {
  count = var.create_worker_kms_key ? 1 : 0

  description             = "AWS KMS customer-managed key (CMK) for Boundary controller & worker"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_cmk_deletion_window
  is_enabled              = true
  enable_key_rotation     = var.kms_cmk_enable_key_rotation
  policy                  = data.aws_iam_policy_document.kms_cmk.json

  tags = merge(
    { Name = "${var.friendly_name_prefix}-boundary-kms-worker-cmk" },
    var.common_tags
  )
}

resource "aws_kms_alias" "worker" {
  count = var.kms_worker_cmk_alias != null ? 1 : 0

  name          = "alias/${var.kms_worker_cmk_alias}"
  target_key_id = aws_kms_key.worker[0].id
}

#------------------------------------------------------------------------------
# KMS Customer Managed Key (CMK) Session Recording (BSR)
#------------------------------------------------------------------------------
resource "aws_kms_key" "bsr" {
  count = var.create_bsr_kms_key ? 1 : 0

  description             = "AWS KMS customer-managed key (CMK) for Boundary Session Recording"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = var.kms_cmk_deletion_window
  is_enabled              = true
  enable_key_rotation     = var.kms_cmk_enable_key_rotation
  policy                  = data.aws_iam_policy_document.kms_cmk.json

  tags = merge(
    { Name = "${var.friendly_name_prefix}-boundary-kms-worker-cmk" },
    var.common_tags
  )
}

resource "aws_kms_alias" "bsr" {
  count = var.kms_bsr_cmk_alias != null && var.create_bsr_kms_key ? 1 : 0

  name          = "alias/${var.kms_bsr_cmk_alias}"
  target_key_id = aws_kms_key.bsr[0].id
}

