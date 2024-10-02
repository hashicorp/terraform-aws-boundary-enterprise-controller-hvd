# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#------------------------------------------------------------------------------
# API Network Load Balancer (lb)
#------------------------------------------------------------------------------
resource "aws_lb" "api" {

  name               = "${var.friendly_name_prefix}-bnd-con-api-lb"
  load_balancer_type = "network"
  internal           = var.api_lb_is_internal
  security_groups    = [aws_security_group.api_lb_allow_ingress.id, aws_security_group.api_lb_allow_egress.id]
  subnets            = var.api_lb_subnet_ids

  tags = merge({ "Name" = "${var.friendly_name_prefix}-boundary-controller-api-lb" }, var.common_tags)
}

resource "aws_lb_listener" "api" {

  load_balancer_arn = aws_lb.api.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.api.arn
  }
}

resource "aws_lb_target_group" "api" {

  name     = "${var.friendly_name_prefix}-bnd-con-api-tg"
  protocol = "TCP"
  port     = 9200
  vpc_id   = var.vpc_id

  health_check {
    protocol            = "HTTPS"
    path                = "/health"
    port                = 9203
    matcher             = "200"
    healthy_threshold   = 5
    unhealthy_threshold = 5
    timeout             = 10
    interval            = 30
  }

  tags = merge(
    { "Name" = "${var.friendly_name_prefix}-boundary-controller-api-tg" },
    { "Description" = "Load Balancer Target Group for Boundary application API traffic." },
    var.common_tags
  )
}

#------------------------------------------------------------------------------
# API lb Security Groups
#------------------------------------------------------------------------------
resource "aws_security_group" "api_lb_allow_ingress" {

  name   = "${var.friendly_name_prefix}-boundary-api-lb-allow-ingress"
  vpc_id = var.vpc_id

  tags = merge({ "Name" = "${var.friendly_name_prefix}-boundary-api-lb-allow-ingress" }, var.common_tags)
}

resource "aws_security_group_rule" "api_lb_allow_ingress_https" {

  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = var.cidr_allow_ingress_boundary_443
  description = "Allow TCP/443 (HTTPS) inbound to lb from specified CIDR ranges."

  security_group_id = aws_security_group.api_lb_allow_ingress.id
}

resource "aws_security_group" "api_lb_allow_egress" {

  name   = "${var.friendly_name_prefix}-boundary-api-lb-allow-egress"
  vpc_id = var.vpc_id
  tags   = merge({ "Name" = "${var.friendly_name_prefix}-boundary-api-lb-allow-egress" }, var.common_tags)
}

resource "aws_security_group_rule" "api_lb_allow_egress_all" {

  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  description = "Allow all traffic outbound from the lb."

  security_group_id = aws_security_group.api_lb_allow_egress.id
}

#------------------------------------------------------------------------------
# Cluster Network Load Balancer (lb)
#------------------------------------------------------------------------------
resource "aws_lb" "cluster" {

  name               = "${var.friendly_name_prefix}-bnd-con-cl-lb"
  load_balancer_type = "network"
  internal           = true
  security_groups    = [aws_security_group.cluster_lb_allow_ingress.id, aws_security_group.cluster_lb_allow_egress.id]
  subnets            = var.cluster_lb_subnet_ids

  tags = merge({ "Name" = "${var.friendly_name_prefix}-boundary-controller-cl-lb" }, var.common_tags)
}

resource "aws_lb_listener" "cluster" {

  load_balancer_arn = aws_lb.cluster.arn
  port              = 9201
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.cluster.arn
  }
}

resource "aws_lb_target_group" "cluster" {

  name     = "${var.friendly_name_prefix}-bnd-con-cl-tg"
  protocol = "TCP"
  port     = 9201
  vpc_id   = var.vpc_id

  health_check {
    protocol            = "HTTPS"
    path                = "/health"
    port                = 9203
    matcher             = "200"
    healthy_threshold   = 5
    unhealthy_threshold = 5
    timeout             = 10
    interval            = 30
  }

  tags = merge(
    { "Name" = "${var.friendly_name_prefix}-boundary-controller-cl-tg" },
    { "Description" = "Load Balancer Target Group for Boundary application cluster traffic." },
    var.common_tags
  )
}

#------------------------------------------------------------------------------
# Cluster lb Security Groups
#------------------------------------------------------------------------------
resource "aws_security_group" "cluster_lb_allow_ingress" {

  name   = "${var.friendly_name_prefix}-boundary-con-cl-lb-allow-ingress"
  vpc_id = var.vpc_id

  tags = merge({ "Name" = "${var.friendly_name_prefix}-boundary-controller-cl-lb-allow-ingress" }, var.common_tags)
}

resource "aws_security_group_rule" "cluster_lb_allow_ingress_cidr_9201" {

  type        = "ingress"
  from_port   = 9201
  to_port     = 9201
  protocol    = "tcp"
  cidr_blocks = var.cidr_allow_ingress_boundary_9201
  description = "Allow TCP/9201 inbound to lb from specified CIDR ranges."

  security_group_id = aws_security_group.cluster_lb_allow_ingress.id
}


resource "aws_security_group_rule" "lb_allow_ingress_sg_9201" {
  for_each = toset(var.sg_allow_ingress_boundary_9201)

  type                     = "ingress"
  from_port                = 9201
  to_port                  = 9201
  protocol                 = "tcp"
  source_security_group_id = each.key
  description              = "Allow TCP/9201 inbound to lb from specified SGs."

  security_group_id = aws_security_group.cluster_lb_allow_ingress.id
}


resource "aws_security_group" "cluster_lb_allow_egress" {

  name   = "${var.friendly_name_prefix}-boundary-con-cl-lb-allow-egress"
  vpc_id = var.vpc_id
  tags   = merge({ "Name" = "${var.friendly_name_prefix}-boundary-controller-cl-lb-allow-egress" }, var.common_tags)
}

resource "aws_security_group_rule" "cluster_lb_allow_egress_all" {

  type        = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
  description = "Allow all traffic outbound from the lb."

  security_group_id = aws_security_group.cluster_lb_allow_egress.id
}

