# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

#------------------------------------------------------------------------------
# RDS password
#------------------------------------------------------------------------------
data "aws_secretsmanager_secret_version" "boundary_database_password" {
  secret_id = var.boundary_database_password_secret_arn
}

#------------------------------------------------------------------------------
# DB Subnet Group
#------------------------------------------------------------------------------
resource "aws_db_subnet_group" "boundary" {
  name       = "${var.friendly_name_prefix}-boundary-db-subnet-group"
  subnet_ids = var.rds_subnet_ids

  tags = merge(
    { "Name" = "${var.friendly_name_prefix}-boundary-db-subnet-group" },
    var.common_tags
  )
}

#------------------------------------------------------------------------------
# RDS Aurora (PostgreSQL)
#------------------------------------------------------------------------------
resource "aws_rds_global_cluster" "boundary" {
  count = var.is_secondary_region == false ? 1 : 0

  global_cluster_identifier = "${var.friendly_name_prefix}-boundary-rds-global-cluster"
  database_name             = var.boundary_database_name
  deletion_protection       = var.rds_deletion_protection
  engine                    = "aurora-postgresql"
  engine_version            = var.rds_aurora_engine_version
  force_destroy             = var.rds_force_destroy
  storage_encrypted         = var.rds_storage_encrypted
}

resource "aws_rds_cluster" "boundary" {
  global_cluster_identifier       = var.is_secondary_region == true ? var.rds_global_cluster_id : aws_rds_global_cluster.boundary[0].id
  cluster_identifier              = "${var.friendly_name_prefix}-boundary-rds-cluster-${data.aws_region.current.name}"
  engine                          = "aurora-postgresql"
  engine_mode                     = var.rds_aurora_engine_mode
  engine_version                  = var.rds_aurora_engine_version
  database_name                   = var.is_secondary_region == true ? null : var.boundary_database_name
  availability_zones              = var.rds_availability_zones
  db_subnet_group_name            = aws_db_subnet_group.boundary.id
  db_cluster_parameter_group_name = aws_rds_cluster_parameter_group.boundary.id
  port                            = 5432
  master_username                 = var.is_secondary_region == true ? null : var.boundary_database_user
  master_password                 = var.is_secondary_region == true ? null : data.aws_secretsmanager_secret_version.boundary_database_password.secret_string
  storage_encrypted               = var.rds_storage_encrypted
  kms_key_id                      = var.rds_kms_key_arn
  vpc_security_group_ids          = [aws_security_group.rds_allow_ingress.id]
  replication_source_identifier   = var.is_secondary_region == true ? var.rds_replication_source_identifier : null
  source_region                   = var.is_secondary_region == true ? var.rds_source_region : null
  backup_retention_period         = var.rds_backup_retention_period
  preferred_backup_window         = var.rds_preferred_backup_window
  preferred_maintenance_window    = var.rds_preferred_maintenance_window
  skip_final_snapshot             = var.rds_skip_final_snapshot
  final_snapshot_identifier       = "${var.friendly_name_prefix}-boundary-rds-final-snapshot-${data.aws_region.current.name}"

  tags = merge(
    { "Name" = "${var.friendly_name_prefix}-boundary-rds-cluster-${data.aws_region.current.name}" },
    { "Description" = "Boundary RDS Aurora PostgreSQL database cluster." },
    { "is_secondary_region" = var.is_secondary_region },
    var.common_tags
  )

  lifecycle {
    ignore_changes = [replication_source_identifier]
  }
}

resource "aws_rds_cluster_instance" "boundary" {
  count = var.rds_aurora_replica_count + 1

  identifier              = "${var.friendly_name_prefix}-boundary-rds-cluster-instance-${count.index}"
  cluster_identifier      = aws_rds_cluster.boundary.id
  instance_class          = var.rds_aurora_instance_class
  engine                  = aws_rds_cluster.boundary.engine
  engine_version          = aws_rds_cluster.boundary.engine_version
  db_parameter_group_name = aws_db_parameter_group.boundary.id
  apply_immediately       = var.rds_apply_immediately
  publicly_accessible     = false

  tags = merge(
    { "Name" = "${var.friendly_name_prefix}-boundary-rds-cluster-instance-${count.index}" },
    { "is_secondary_region" = var.is_secondary_region },
    var.common_tags
  )
}

resource "aws_rds_cluster_parameter_group" "boundary" {
  name        = "${var.friendly_name_prefix}-boundary-rds-cluster-parameter-group-${data.aws_region.current.name}"
  family      = var.rds_parameter_group_family
  description = "Boundary RDS Aurora PostgreSQL database cluster parameter group."
}

resource "aws_db_parameter_group" "boundary" {
  name        = "${var.friendly_name_prefix}-boundary-rds-db-parameter-group-${data.aws_region.current.name}"
  family      = var.rds_parameter_group_family
  description = "Boundary RDS Aurora PostgreSQL database cluster instance parameter group."
}

#------------------------------------------------------------------------------
# RDS Security Group
#------------------------------------------------------------------------------
resource "aws_security_group" "rds_allow_ingress" {
  name   = "${var.friendly_name_prefix}-boundary-rds-allow-ingress"
  vpc_id = var.vpc_id
  tags   = merge({ "Name" = "${var.friendly_name_prefix}-boundary-rds-allow-ingress" }, var.common_tags)
}

resource "aws_security_group_rule" "rds_allow_ingress_from_ec2" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.ec2_allow_ingress.id
  description              = "Allow TCP/5432 (PostgreSQL) inbound to RDS Aurora from Boundary EC2 instances."

  security_group_id = aws_security_group.rds_allow_ingress.id
}

