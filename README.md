# letsencrypt-aws

`letsencrypt-aws` is a program that can be run in the background which
automatically provisions and updates certificates on your AWS infrastructure
using the AWS APIs and Let's Encrypt.

## How it works

`letsencrypt-aws` takes a list of ELBs, and which hosts you want them to be
able to serve. It runs in a loop and every day does the following:

It gets the certificate for that ELB. If the certificate is going to expire
soon (in less than 45 days), it generates a new private key and CSR and sends a
request to Let's Encrypt. It takes the DNS challenge and creates a record in
Route53 for that challenge. This completes the Let's Encrypt challenge and we
receive a certificate. It uploads the new certificate and private key to IAM
and updates your ELB to use the certificate.

In theory all you need to do is make sure this is running somewhere, and your
ELBs' certificates will be kept minty fresh.

## How to run it

Before you can use `letsencrypt-aws` you need to have created an account with
the ACME server (you only need to do this the first time). You can register
using (if you already have an account you can skip this step):

```console
$ # If you're trying to register for a server besides the Let's Encrypt
$ # production one, see the configuration documentation below.
$ python letsencrypt-aws.py register email@host.com
2016-01-09 19:56:19 [acme-register.generate-key]
2016-01-09 19:56:20 [acme-register.register] email=u'email@host.com'
2016-01-09 19:56:21 [acme-register.agree-to-tos]
-----BEGIN RSA PRIVATE KEY-----
[...]
-----END RSA PRIVATE KEY-----
```

You'll need to put the private key somewhere that `letsencrypt-aws` can access
it (either on the local filesystem or in S3).

You will also need to have your AWS credentials configured. You can use any of
the [mechanisms documented by
boto3](https://boto3.readthedocs.org/en/latest/guide/configuration.html), or
use IAM instance profiles (which are supported, but not mentioned by the
`boto3` documentation). See below for which AWS permissions are required.

`letsencrypt-aws` takes it's configuration via the `LETSENCRYPT_AWS_CONFIG`
environment variable. This should be a JSON object with the following schema:

```json
{
    "domains": [
        {
            "elb": {
                "name": "ELB name (string)",
                "port": "optional, defaults to 443 (integer)"
            },
            "hosts": ["list of hosts you want on the certificate (strings)"],
            "key_type": "rsa or ecdsa, optional, defaults to rsa (string)"
        }
    ],
    "acme_account_key": "location of the account private key (string)",
    "acme_directory_url": "optional, defaults to Let's Encrypt production (string)"
}
```

The `acme_account_key` can either be located on the local filesystem or in S3.
To specify a local file you provide `"file:///path/to/key.pem"`, for S3 provide
`"s3://bucket-nam/object-name"`. The key should be a PEM formatted RSA private
key.

Then you can simply run it: `python letsencrypt-aws.py update-certificates`.

If you add the `--persistent` flag it will run forever, rather than just once,
sleeping for 24 hours between each check for certificate expiration. This is
useful for production environments.

If your certificate is not expiring soon, but you need to issue a new one
anyways, the `--force-issue` flag can be provided.

If you're into [Docker](https://www.docker.com/), there is an automatically
built image of `letsencrypt-aws` available as
[`alexgaynor/letsencrypt-aws`](https://hub.docker.com/r/alexgaynor/letsencrypt-aws/).

## Operational Security

Keeping the source of your certificates secure is, for obvious reasons,
important. `letsencrypt-aws` relies heavily on the AWS APIs to do its
business, so we recommend running this code from EC2, so that you can use the
Metadata service for managing credentials. You can give your EC2 instance an
IAM instance profile with permissions to manage the relevant services (see
below for complete details).

You need to make sure that the ACME account private key is kept secure. The
best choice is probably in an S3 bucket with encryption enabled and access
limited with IAM.

Finally, wherever you're running `letsencrypt-aws` needs to be trusted.
`letsencrypt-aws` generates private keys in memory and uploads them to IAM
immediately, they are never stored on disk.

### IAM Policy

The minimum set of permissions needed for `letsencrypt-aws` to work is:

* `route53:ChangeResourceRecordSets`
* `route53:GetChange`
* `route53:ListHostedZones`
* `elasticloadbalancing:DescribeLoadBalancers`
* `elasticloadbalancing:SetLoadBalancerListenerSSLCertificate`
* `iam:ListServerCertificates`
* `iam:UploadServerCertificate`
* `iam:GetServerCertificate`

If your `acme_account_key` is provided as an `s3://` URI you will also need:

* `s3:GetObject`

It's likely possible to restrict these permissions by ARN, though this has not
been fully explored.

An example IAM policy is:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "route53:ChangeResourceRecordSets",
                "route53:GetChange",
                "route53:GetChangeDetails",
                "route53:ListHostedZones"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "elasticloadbalancing:DescribeLoadBalancers",
                "elasticloadbalancing:SetLoadBalancerListenerSSLCertificate"
            ],
            "Resource": [
                "*"
            ]
        },
        {
            "Sid": "",
            "Effect": "Allow",
            "Action": [
                "iam:ListServerCertificates",
                "iam:GetServerCertificate",
                "iam:UploadServerCertificate"
            ],
            "Resource": [
                "*"
            ]
        }
    ]
}
```
