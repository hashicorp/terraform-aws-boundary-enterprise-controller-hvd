# Boundary Controller Certificate Rotation

One of the required prerequisites to deploying this module is storing base64-encoded strings of your Boundary Controller TLS/SSL certificate and private key files in PEM format as plaintext secrets within AWS Secrets Manager for bootstrapping automation purposes. The Boundary Controller EC2 cloud-init (user_data) script is designed to retrieve the latest value of these secrets every time it runs. Therefore, the process for updating Boundary Controller's TLS/SSL certificates are to update the values of the corresponding secrets in AWS Secrets Manager, and then to replace the running EC2 instance(s) within the Autoscaling Group such that when the new instance(s) spawn and re-install Boundary Controller, they pick up the new certs. See the section below for detailed steps.

## Secrets

| Certificate file    | Module input variable        |
|---------------------|------------------------------|
| TLS/SSL certificate | `boundary_tls_cert_secret_arn`    |
| TLS/SSL private key | `boundary_tls_privkey_secret_arn` |

## Procedure

Follow these steps to rotate the certificates for your Boundary Controller instance.

1. Obtain your new Boundary Controller TLS/SSL certificate file and private key file, both in PEM format.

2. Update the values of the existing secrets in AWS Secrets Manager (`boundary_tls_cert_secret_arn` and `boundary_tls_privkey_secret_arn`, respectively). If you need assistance base64-encoding the files into strings prior to updating the secrets, see the examples below:

    On Linux (bash):

    ```sh
    cat new_boundary_cert.pem | base64 -w 0
    cat new_boundary_privkey.pem | base64 -w 0
    ```

   On macOS (terminal):

   ```sh
   cat new_boundary_cert.pem | base64
   cat new_boundary_privkey.pem | base64
   ```

   On Windows (PowerShell):

   ```powershell
   function ConvertTo-Base64 {
    param (
        [Parameter(Mandatory=$true)]
        [string]$InputString
    )
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $EncodedString = [Convert]::ToBase64String($Bytes)
    return $EncodedString
   }

   Get-Content new_boundary_cert.pem -Raw | ConvertTo-Base64 -Width 0
   Get-Content new_boundary_privkey.pem -Raw | ConvertTo-Base64 -Width 0
   ```

    > **Note:**
    > When you update the value of an AWS Secrets Manager secret, the secret ARN should not change, so **no action should be needed** in terms of updating any input variable values. If the secret ARNs _were_ to change due to other circumstances, you would need to update the following input variable values with the new ARNs, and subsequently run `terraform apply` to update the Boundary Controller EC2 Launch Template:
   >
    >```hcl
    >boundary_tls_cert_secret_arn    = "<new-boundary-tls-cert-secret-arn>"
    >boundary_tls_privkey_secret_arn = "<new-boundary-tls-privkey-secret-arn>"
    >```

3. During a maintenance window, terminate the running Boundary Controller EC2 instance(s) which will trigger the Autoscaling Group to spawn new instance(s) from the latest version of the Boundary Controller EC2 Launch Template. This process will effectively re-install Boundary Controller on the new instance(s), including the retrieval of the latest certificates from the AWS Secrets Manager secrets.
