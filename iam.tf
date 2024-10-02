# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "aws_iam_policy_document" "assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    effect  = "Allow"
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "rds_kms" {
  count = var.rds_kms_key_arn != null ? 1 : 0

  statement {
    sid    = "ManageRDSKmsKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      var.rds_kms_key_arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_root_kms_created" {
  count = var.create_root_kms_key ? 1 : 0

  statement {
    sid    = "BoundaryRootCreatedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      aws_kms_key.root[0].arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_recovery_kms_created" {
  count = var.create_recovery_kms_key ? 1 : 0

  statement {
    sid    = "BoundaryRecoveryCreatedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      aws_kms_key.recovery[0].arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_worker_kms_created" {
  count = var.create_worker_kms_key ? 1 : 0

  statement {
    sid    = "BoundaryWorkerCreatedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      aws_kms_key.worker[0].arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_bsr_kms_created" {
  count = var.enable_session_recording && var.create_bsr_kms_key ? 1 : 0

  statement {
    sid    = "BoundaryBSRCreatedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      aws_kms_key.bsr[0].arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_root_kms_provided" {
  count = var.root_kms_key_arn != null ? 1 : 0

  statement {
    sid    = "BoundaryRootProvidedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      data.aws_kms_key.root[0].arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_recovery_kms_provided" {
  count = var.recovery_kms_key_arn != null ? 1 : 0

  statement {
    sid    = "BoundaryRecoveryProvidedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      data.aws_kms_key.recovery[0].arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_worker_kms_provided" {
  count = var.worker_kms_key_arn != null ? 1 : 0

  statement {
    sid    = "BoundaryWorkerProvidedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      data.aws_kms_key.worker[0].arn
    ]
  }
}

data "aws_iam_policy_document" "boundary_bsr_kms_provided" {
  count = var.enable_session_recording && var.bsr_kms_key_arn != null ? 1 : 0

  statement {
    sid    = "BoundaryBSRProvidedKMSKey"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:Encrypt",
      "kms:DescribeKey",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*"
    ]
    resources = [
      data.aws_kms_key.bsr[0].arn
    ]
  }
}

# data "aws_iam_policy_document" "boundary_kms" {

#   statement {
#     sid    = "BoundaryKMSKey"
#     effect = "Allow"
#     actions = [
#       "kms:Decrypt",
#       "kms:Encrypt",
#       "kms:DescribeKey",
#       "kms:ReEncrypt*",
#       "kms:GenerateDataKey*"
#     ]
#     resources = [
#       aws_kms_key.root.arn,
#       aws_kms_key.recovery.arn,
#       aws_kms_key.worker.arn
#     ]
#   }
# }

# data "aws_iam_policy_document" "boundary_bsr_kms" {
#   count = var.enable_session_recording == true ? 1 : 0

#   statement {
#     sid    = "BoundaryBSRKMSKey"
#     effect = "Allow"
#     actions = [
#       "kms:Decrypt",
#       "kms:Encrypt",
#       "kms:DescribeKey",
#       "kms:ReEncrypt*",
#       "kms:GenerateDataKey*"
#     ]
#     resources = [
#       aws_kms_key.bsr[0].arn
#     ]
#   }
# }

data "aws_iam_policy_document" "license" {
  count = var.boundary_license_secret_arn != null ? 1 : 0

  statement {
    sid     = "BoundaryLicense"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      var.boundary_license_secret_arn,
    ]
  }
}

data "aws_iam_policy_document" "db" {
  count = var.boundary_database_password_secret_arn != null ? 1 : 0

  statement {
    sid     = "BoundaryDBPassword"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      var.boundary_database_password_secret_arn,
    ]
  }
}

data "aws_iam_policy_document" "tls_cert" {
  count = var.boundary_tls_cert_secret_arn != null ? 1 : 0

  statement {
    sid     = "BoundaryTLSCert"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      var.boundary_tls_cert_secret_arn,
    ]
  }
}

data "aws_iam_policy_document" "tls_privkey" {
  count = var.boundary_tls_privkey_secret_arn != null ? 1 : 0
  statement {
    sid     = "BoundaryTLSPrivKey"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      var.boundary_tls_privkey_secret_arn,
    ]
  }
}
data "aws_iam_policy_document" "tls_ca" {
  count = var.boundary_tls_ca_bundle_secret_arn != null ? 1 : 0
  statement {
    sid     = "BoundaryTLSCABundle"
    effect  = "Allow"
    actions = ["secretsmanager:GetSecretValue"]
    resources = [
      var.boundary_tls_ca_bundle_secret_arn
    ]
  }
}

data "aws_iam_policy_document" "combined" {
  source_policy_documents = [

    var.create_root_kms_key ? data.aws_iam_policy_document.boundary_root_kms_created[0].json : "",
    var.create_recovery_kms_key ? data.aws_iam_policy_document.boundary_recovery_kms_created[0].json : "",
    var.create_worker_kms_key ? data.aws_iam_policy_document.boundary_worker_kms_created[0].json : "",
    var.enable_session_recording && var.create_bsr_kms_key ? data.aws_iam_policy_document.boundary_bsr_kms_created[0].json : "",
    var.root_kms_key_arn != null ? data.aws_iam_policy_document.boundary_root_kms_provided[0].json : "",
    var.recovery_kms_key_arn != null ? data.aws_iam_policy_document.boundary_recovery_kms_provided[0].json : "",
    var.worker_kms_key_arn != null ? data.aws_iam_policy_document.boundary_worker_kms_provided[0].json : "",
    var.enable_session_recording && var.bsr_kms_key_arn != null ? data.aws_iam_policy_document.boundary_bsr_kms_provided[0].json : "",
    # data.aws_iam_policy_document.boundary_kms.json,
    # var.enable_session_recording == true ? data.aws_iam_policy_document.boundary_bsr_kms[0].json : "",
    var.rds_kms_key_arn != null ? data.aws_iam_policy_document.rds_kms[0].json : "",
    var.boundary_license_secret_arn != null ? data.aws_iam_policy_document.license[0].json : "",
    var.boundary_database_password_secret_arn != null ? data.aws_iam_policy_document.db[0].json : "",
    var.boundary_tls_cert_secret_arn != null ? data.aws_iam_policy_document.tls_cert[0].json : "",
    var.boundary_tls_privkey_secret_arn != null ? data.aws_iam_policy_document.tls_privkey[0].json : "",
    var.boundary_tls_ca_bundle_secret_arn != null ? data.aws_iam_policy_document.tls_ca[0].json : "",
  ]
}

resource "aws_iam_role_policy" "boundary_ec2" {
  name   = "${var.friendly_name_prefix}-boundary-controller-instance-role-policy-${data.aws_region.current.name}"
  role   = aws_iam_role.boundary_ec2.id
  policy = data.aws_iam_policy_document.combined.json
}

resource "aws_iam_instance_profile" "boundary_ec2" {
  name = "${var.friendly_name_prefix}-boundary-controller-instance-profile-${data.aws_region.current.name}"
  path = "/"
  role = aws_iam_role.boundary_ec2.name
}

resource "aws_iam_role_policy_attachment" "aws_ssm" {
  count = var.ec2_allow_ssm == true ? 1 : 0

  role       = aws_iam_role.boundary_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role" "boundary_ec2" {
  name = "${var.friendly_name_prefix}-boundary-controller-instance-role-${data.aws_region.current.name}"
  path = "/"

  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json

  tags = merge({ "Name" = "${var.friendly_name_prefix}-boundary-controller-instance-role" }, var.common_tags)
}
