# Deployment Customizations

On this page are various deployment customizations and their corresponding input variables that you may set to meet your requirements.

## Load Balancing

This module creates two Network Load Balancer (NLB) for the Boundary Controller. The first one is used for the API and can either be internal or external. Boundary Clients will use this NLB for communicating the Boundary Controllers. **The default is internal**, but the following module boolean input variable may be set to configure the load balancer to be `external` (internet-facing) if desirable.

```hcl
api_lb_is_internal = false
```

The second NLB is used for Cluster communication. This is set to be `internal` and is not open to the internet. This is used as the upstream for Boundary Ingress Workers.

## DNS

This module supports creating an _alias_ record in AWS Route53 for the Boundary FQDN to resolve to the Boundary API load balancer DNS name. To do so, the following module input variables may be set:

```hcl
create_route53_boundary_dns_record      = <true>
route53_boundary_hosted_zone_name       = "<example.com>"
route53_boundary_hosted_zone_is_private = <false>
```

## KMS

If you require the use of a customer-managed key(s) (CMK) to encrypt your AWS resources, the following module input variables may be set:

```hcl
ebs_kms_key_arn   = "<ebs-kms-key-arn>"
rds_kms_key_arn   = "<rds-kms-key-arn>"
```

## Custom AMI

If you have a custom AWS AMI you would like to use, you can specify it via the following module input variables:

```hcl
ec2_ami_id    = "<custom-rhel-ami-id>"
ec2_os_distro = "<rhel>"
```

## Deployment Troubleshooting

In the `compute.tf` there is a commented out local file resource that will render the Boundary custom data script to a local file where this module is being run. This can be useful for reviewing the custom data script as it will be rendered on the deployed VM. This fill will contain sensitive vaults so do not commit this and delete this file when done troubleshooting.
