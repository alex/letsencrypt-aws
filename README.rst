letsencrypt-aws
===============

This will eventually be a program that can be run in the background which
automatically provisions and updates certificates on your AWS infrastructure.

Status
------

**This is currently in development. It doesn't work. It will not be usable
until Let's Encrypt officially launches DNS challenges.**

DNS challenges are currently available in the Let's Encrypt staging
environment, however there are (at least) a few blockers:

* https://github.com/letsencrypt/boulder/pull/1295
* https://github.com/letsencrypt/letsencrypt/pull/2061

How it works
------------

``letsencrypt-aws`` takes a list of ELBs, and which hosts you want them to be
able to serve. It runs in a loop and every day does the following:

It gets the certificate for that ELB. If the certificate is going to expire
soon, it generates a new private key and CSR and sends a request to Let's
Encrypt. It takes the DNS challenge and creates a record in Route53 for that
challenge. This completes the Let's Encrypt challenge and we receive a
certificate. It uploads the new certificate and private key to IAM and updates
your ELB to use the certificate.

In theory all you need to do is make sure this is running somewhere, and your
ELBs' certificates will be kept minty fresh.

How to run it
-------------

Before you can use ``letsencrypt-aws`` you need to have created an account with
the ACME server. Documentation for how to do this is outside the scope of
``letsencrypt-aws``. You'll need to put the private key somewhere that
``letsencrypt-aws`` can access it (either on the local filesystem or in S3).

``letsencrypt-aws`` takes it's configuration via the ``LETSENCRYPT_AWS_CONFIG``
environment variable. This should be a JSON object with the following schema:

.. code-block:: json

    {
        "domains": [
            {
                "elb": {
                    "name": "ELB name (string)",
                    "port": "optional, defaults to 443 (integer)"
                },
                "hosts": ["list of hosts you want on the certificate (strings)"]
            }
        ],
        "acme_account_key": "location of the account private key (string)",
        "acme_directory_url": "optional, can be used to test with staging (string)"
    }

The ``acme_account_key`` can either be located on the local filesystem or in
S3. To specify a local file you provide ``"file:///path/to/key.pem"``, for S3
provide ``"s3://bucket-nam/object-name"``. The key should be a PEM formatted
RSA private key.

Then you can simply run it: ``python letsencrypt-aws.py``.

If you add the ``--persistent`` flag it will run forever, rather than just
once. This is useful for production environments.

Operational Security
--------------------

Keeping the source of your certificates secure is, for obvious reasons,
important. ``letsencrypt-aws`` relies heavily on the AWS APIs to do its
business, so we recommend running this code from EC2, so that you can use the
Metadata service for managing credentials. You can give your EC2 instance an
IAM instance profile with permissions to manage the relevant services (ELB,
IAM, Route53).

You need to make sure that the ACME account private key is kept secure. The
best choice is probably in an S3 bucket with encryption enabled and access
limited.

Finally, wherever you're running ``letsencrypt-aws`` needs to be trusted.
``letsencrypt-aws`` generates private keys in memory and uploads them to IAM
immediately, they are never stored on disk.

IAM Policy
~~~~~~~~~~

The minimum set of permissions needed for ``letsencrypt-aws`` to work is:

* ``route53:ChangeResourceRecordSets``
* ``route53:GetChange``
* ``route53:ListHostedZones``
* ``elasticloadbalancing:DescribeLoadBalancers``
* ``elasticloadbalancing:SetLoadBalancerListenerSSLCertificate``
* ``iam:ListServerCertificates``
* ``iam:UploadServerCertificate``

If your ``acme_account_key`` is provided as an ``s3://`` URI you will also
need:

* ``s3:GetObject``

It's likely possible to restrict these permissions by ARN, though this has not
been fully explored.
