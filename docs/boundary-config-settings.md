# Boundary Configuration Settings

In order to bootstrap and automate the deployment of Boundary controller, the [boundary_custom_data.sh](../templates/boundary_custom_data.sh.tpl) dynamically generates a boundary controller config file containing the Boundary controller configuration settings before ultimately bringing up the application. Some of these settings values are derived from input variables, some are interpolated directly from other infrastructure resources that are created by the module, and some are computed for you.

Because we have bootstrapped and automated the Boundary controller deployment, and our Boundary controller application data is decoupled from the VM(s), the VMs are stateless, ephemeral, and are treated as _immutable_. Therefore, the process of updating or modifying a Boundary configuration setting involves replacing/re-imaging the VMs within the Boundary controller Auto Scaling Group (ASG), rather than modifying the running VMs in-place. You should not update or modify settings in-place on your running Boundary EC2 instance(s), unless it is to temporarily test or troubleshoot something prior to making a code change.

## Configuration Settings Reference

The [Boundary controller stanza configuration reference](https://developer.hashicorp.com/boundary/docs/configuration/controller) page contains all of the available settings, their descriptions, and their default values. If you would like to configure one of these settings for your Boundary controller deployment with a non-default value, then look to see if the setting is defined in the [variables.tf](../variables.tf) of this module. If so, you can set the variable and desired value within your own root Terraform configuration that deploys this module, and subsequently run Terraform to update (re-image/replace) the VMs within your Boundary Controller ASG.

## Where to Look in the Code

Within the [compute.tf](../compute.tf) file, you will see a `locals` block with a map inside of it called `custom_data_args`. Almost all of the Boundary configuration settings are passed from here as arguments into the [boundary_custom_data.sh](../templates/boundary_custom_data.sh.tpl) (cloud-init) script.

Within the [boundary_custom_data.sh](../templates/boundary_custom_data.sh.tpl) script there is a function named `generate_boundary_config` that is responsible for receiving all of those inputs and dynamically generating the `controller.hcl` file. After a successful install process, this can be found on your Boundary VM(s) within `/etc/boundary.d/controller.hcl`.
