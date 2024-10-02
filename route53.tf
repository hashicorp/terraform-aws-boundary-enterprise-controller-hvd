# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "aws_route53_zone" "boundary" {
  count = var.create_route53_boundary_dns_record == true && var.route53_boundary_hosted_zone_name != null ? 1 : 0

  name         = var.route53_boundary_hosted_zone_name
  private_zone = var.route53_boundary_hosted_zone_is_private
}

resource "aws_route53_record" "alias_record" {
  count = var.route53_boundary_hosted_zone_name != null && var.create_route53_boundary_dns_record == true ? 1 : 0

  name    = var.boundary_fqdn
  zone_id = data.aws_route53_zone.boundary[0].zone_id
  type    = "A"

  alias {
    name                   = aws_lb.api.dns_name
    zone_id                = aws_lb.api.zone_id
    evaluate_target_health = true
  }
}