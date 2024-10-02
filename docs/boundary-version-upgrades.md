# Boundary Version Upgrades

See the [Boundary Releases](https://developer.hashicorp.com/boundary/docs/release-notes) page for full details on the releases. Since we have bootstrapped and automated the Boundary Controller deployment and the Boundary Controller application data is decoupled from the compute (EC2) layer, the EC2 instance(s) are stateless, ephemeral, and are treated as immutable. Therefore, the process of upgrading your Boundary Controller instance to a new version involves updating your Terraform code managing your Boundary deployment to reflect the new version, applying the change via Terraform to update the Boundary EC2 Launch Template, and then replacing running EC2 instance(s) within the Autoscaling Group.

This module includes an input variable named `boundary_version` that dictates which version of Boundary is deployed. Here are the steps to follow:

## Procedure

 Here are the steps to follow:

1. Determine your desired version of Boundary from the [Boundary Release Notes](https://developer.hashicorp.com/boundary/docs/release-notes) page.

2. Out of precaution, generate a backup of your RDS Aurora PostgreSQL database.

3. Update the value of the `boundary_version` input variable within your `terraform.tfvars` file. Also update `asg_instance_count` to 1.

   ```hcl
   boundary_version = "0.17.1+ent"
    ```

4. From within the directory managing your Boundary deployment, run `terraform apply` to update the Boundary EC2 Launch Template.

5. During a maintenance window, terminate the running Boundary EC2 instance(s) which will trigger the Autoscaling Group to spawn new instance(s) from the latest version of the Boundary EC2 Launch Template. This process will effectively re-install Boundary on the new instance(s).

6. Ensure that the EC2 instance(s) within the Boundary controller have been replaced/re-imaged with the changes. Monitor the cloud-init processes to ensure a successful re-install.

7. After the Boundary service has started, it may fail requiring a database migration. To perform the migration, on the controller run this command `boundary database migrate -config /etc/boundary.d/controller.hcl`. This will perform the database migration and the Boundary service can be started.

8. Update the value of the `asg_instance_count` input variable within your `terraform.tfvars` file to the previous value.

9. From within the directory managing your Boundary deployment, run `terraform apply` to scale out the deployment.