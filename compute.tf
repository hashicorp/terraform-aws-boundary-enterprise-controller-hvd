# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#------------------------------------------------------------------------------
# User Data (cloud-init) arguments
#------------------------------------------------------------------------------
locals {
  custom_install_tpl          = var.custom_install_template != null ? "${path.cwd}/templates/${var.custom_install_template}" : "${path.module}/templates/boundary_custom_data.sh.tpl"
  user_data_template_rendered = templatefile(local.custom_install_tpl, local.custom_data_args)
  custom_data_args = {

    # https://developer.hashicorp.com/boundary/docs/configuration/controller

    # prereqs
    boundary_license_secret_arn       = var.boundary_license_secret_arn
    boundary_tls_cert_secret_arn      = var.boundary_tls_cert_secret_arn
    boundary_tls_privkey_secret_arn   = var.boundary_tls_privkey_secret_arn
    boundary_tls_ca_bundle_secret_arn = var.boundary_tls_ca_bundle_secret_arn == null ? "NONE" : var.boundary_tls_ca_bundle_secret_arn
    additional_package_names          = join(" ", var.additional_package_names)

    # Boundary settings
    boundary_version     = var.boundary_version
    systemd_dir          = "/etc/systemd/system",
    boundary_dir_bin     = "/usr/bin",
    boundary_dir_config  = "/etc/boundary.d",
    boundary_dir_home    = "/opt/boundary",
    boundary_install_url = format("https://releases.hashicorp.com/boundary/%s/boundary_%s_linux_amd64.zip", var.boundary_version, var.boundary_version),
    boundary_tls_disable = var.boundary_tls_disable

    # Database settings
    boundary_database_host       = "${aws_rds_cluster.boundary.endpoint}:5432"
    boundary_database_name       = aws_rds_cluster.boundary.database_name
    boundary_database_user       = aws_rds_cluster.boundary.master_username
    boundary_database_password   = aws_rds_cluster.boundary.master_password
    boundary_database_parameters = var.boundary_database_parameters

    # KMS settings
    aws_region      = data.aws_region.current.name
    root_kms_id     = var.root_kms_key_arn != null ? data.aws_kms_key.root[0].id : aws_kms_key.root[0].id
    recovery_kms_id = var.recovery_kms_key_arn != null ? data.aws_kms_key.recovery[0].id : aws_kms_key.recovery[0].id
    worker_kms_id   = var.worker_kms_key_arn != null ? data.aws_kms_key.worker[0].id : aws_kms_key.worker[0].id
    bsr_kms_id      = try(data.aws_kms_key.bsr[0].id, aws_kms_key.bsr[0].id, "")
    kms_endpoint    = var.kms_endpoint
  }
}

#------------------------------------------------------------------------------
# Launch Template
#------------------------------------------------------------------------------
locals {
  // If an AMI ID is provided via `var.ec2_ami_id`, use it.
  // Otherwise, use the latest AMI for the specified OS distro via `var.ec2_os_distro`.
  ami_id_list = tolist([
    var.ec2_ami_id,
    join("", data.aws_ami.ubuntu.*.image_id),
    join("", data.aws_ami.rhel.*.image_id),
    join("", data.aws_ami.centos.*.image_id),
    join("", data.aws_ami.amzn2.*.image_id),
  ])
}

resource "aws_launch_template" "boundary" {
  name          = "${var.friendly_name_prefix}-boundary-ec2-launch-template"
  image_id      = coalesce(local.ami_id_list...)
  instance_type = var.ec2_instance_size
  key_name      = var.ec2_ssh_key_pair
  user_data     = base64gzip(local.user_data_template_rendered)

  iam_instance_profile {
    name = aws_iam_instance_profile.boundary_ec2.name
  }

  vpc_security_group_ids = [
    aws_security_group.ec2_allow_ingress.id,
    aws_security_group.ec2_allow_egress.id
  ]

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_type = var.ebs_volume_type
      volume_size = var.ebs_volume_size
      throughput  = var.ebs_throughput
      iops        = var.ebs_iops
      encrypted   = var.ebs_is_encrypted
      kms_key_id  = var.ebs_is_encrypted == true && var.ebs_kms_key_arn != "" ? var.ebs_kms_key_arn : null
    }
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }

  tag_specifications {
    resource_type = "instance"

    tags = merge(
      { "Name" = "${var.friendly_name_prefix}-boundary-controller-ec2" },
      { "Type" = "autoscaling-group" },
      { "OS_Distro" = var.ec2_os_distro },
      var.common_tags
    )
  }

  tags = merge(
    { "Name" = "${var.friendly_name_prefix}-boundary-controller-ec2-launch-template" },
    var.common_tags
  )
}

#------------------------------------------------------------------------------
# Autoscaling Group
#------------------------------------------------------------------------------
resource "aws_autoscaling_group" "boundary" {
  name                      = "${var.friendly_name_prefix}-boundary-controller-asg"
  min_size                  = 0
  max_size                  = var.asg_max_size
  desired_capacity          = var.asg_instance_count
  vpc_zone_identifier       = var.controller_subnet_ids
  health_check_grace_period = var.asg_health_check_grace_period
  health_check_type         = "ELB"

  launch_template {
    id      = aws_launch_template.boundary.id
    version = "$Latest"
  }

  target_group_arns = [aws_lb_target_group.api.arn, aws_lb_target_group.cluster.arn]

  tag {
    key                 = "Name"
    value               = "${var.friendly_name_prefix}-boundary-controller-asg"
    propagate_at_launch = false
  }

  dynamic "tag" {
    for_each = var.common_tags

    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = false
    }
  }
}

#------------------------------------------------------------------------------
# Security Groups
#------------------------------------------------------------------------------
resource "aws_security_group" "ec2_allow_ingress" {
  name   = "${var.friendly_name_prefix}-boundary-controller-ec2-allow-ingress"
  vpc_id = var.vpc_id
  tags   = merge({ "Name" = "${var.friendly_name_prefix}-boundary-controller-ec2-allow-ingress" }, var.common_tags)
}

resource "aws_security_group_rule" "ec2_allow_ingress_9200_from_api_lb" {

  type                     = "ingress"
  from_port                = 9200
  to_port                  = 9200
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.api_lb_allow_ingress.id
  description              = "Allow TCP/9200 inbound to Boundary Controller EC2 instances from Boundary api load balancer."

  security_group_id = aws_security_group.ec2_allow_ingress.id
}

resource "aws_security_group_rule" "ec2_allow_ingress_9201_from_cluster_lb" {

  type                     = "ingress"
  from_port                = 9201
  to_port                  = 9201
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster_lb_allow_ingress.id
  description              = "Allow TCP/9201 inbound to Boundary Controller EC2 instances from Boundary cluster load balancer."

  security_group_id = aws_security_group.ec2_allow_ingress.id
}

resource "aws_security_group_rule" "ec2_allow_ingress_9201_cidr" {
  count = var.cidr_allow_ingress_boundary_9201 != null ? 1 : 0

  type        = "ingress"
  from_port   = 9201
  to_port     = 9201
  protocol    = "tcp"
  cidr_blocks = var.cidr_allow_ingress_boundary_9201
  description = "Allow TCP/9201 inbound to Boundary Controller EC2 instances from specified CIDR ranges for ingress workers."

  security_group_id = aws_security_group.ec2_allow_ingress.id
}

resource "aws_security_group_rule" "ec2_allow_ingress_9201_sg" {
  for_each = toset(var.sg_allow_ingress_boundary_9201)

  type                     = "ingress"
  from_port                = 9201
  to_port                  = 9201
  protocol                 = "tcp"
  source_security_group_id = each.key
  description              = "Allow TCP/9201 inbound to Boundary Controller EC2 instances from specified Security Groups for ingress workers."

  security_group_id = aws_security_group.ec2_allow_ingress.id
}

resource "aws_security_group_rule" "ec2_allow_ingress_9203_from_api_lb" {

  type                     = "ingress"
  from_port                = 9203
  to_port                  = 9203
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.api_lb_allow_ingress.id
  description              = "Allow TCP/9203 inbound to Boundary Controller EC2 instances from Boundary load balancer."

  security_group_id = aws_security_group.ec2_allow_ingress.id
}

resource "aws_security_group_rule" "ec2_allow_ingress_9203_from_cluster_lb" {

  type                     = "ingress"
  from_port                = 9203
  to_port                  = 9203
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.cluster_lb_allow_ingress.id
  description              = "Allow TCP/9203 inbound to Boundary Controller EC2 instances from Boundary load balancer."

  security_group_id = aws_security_group.ec2_allow_ingress.id
}

resource "aws_security_group_rule" "ec2_allow_ingress_ssh" {
  count = length(var.cidr_allow_ingress_ec2_ssh) > 0 ? 1 : 0

  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = var.cidr_allow_ingress_ec2_ssh
  description = "Allow TCP/22 (SSH) inbound to Boundary Controller EC2 instances from specified CIDR ranges."

  security_group_id = aws_security_group.ec2_allow_ingress.id
}

resource "aws_security_group" "ec2_allow_egress" {
  name   = "${var.friendly_name_prefix}-boundary-controller-ec2-allow-egress"
  vpc_id = var.vpc_id
  tags   = merge({ "Name" = "${var.friendly_name_prefix}-boundary-ec2-controller-allow-egress" }, var.common_tags)
}

resource "aws_security_group_rule" "ec2_allow_egress_all" {

  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  description = "Allow all traffic outbound from Boundary Controller EC2 instances."

  security_group_id = aws_security_group.ec2_allow_egress.id
}

resource "aws_security_group_rule" "ec2_allow_egress_rds" {
  type                     = "egress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.rds_allow_ingress.id
  description              = "Allow TCP/443 (HTTPS) egress from Boundary Controller EC2 instances to specified CIDR ranges."

  security_group_id = aws_security_group.ec2_allow_egress.id
}

# ------------------------------------------------------------------------------
# Debug rendered boundary custom_data script from template
# ------------------------------------------------------------------------------
# Uncomment this block to debug the rendered boundary custom_data script
# resource "local_file" "debug_custom_data" {
#   content  = templatefile("${path.module}/templates/boundary_custom_data.sh.tpl", local.custom_data_args)
#   filename = "${path.module}/debug/debug_boundary_custom_data.sh"
# }
