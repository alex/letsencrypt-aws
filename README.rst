letsencrypt-aws
===============

**This is currently in development. It doesn't work. It will not be possible
until Lets Encrypt officially launches DNS challenges.**

This will eventually be a program that can be run in the background which
automatically provisions and updates certificates on your AWS infrastructure.

How it works
------------

``letsencrypt-aws`` takes a list of ELBs, and which hosts you want them to be
able to serve. It runs in a loop and every day does the following:

It gets the certificate for that ELB. If the certificate is going to expire
soon, it generates a new private key and CSR and sends a request to Lets
Encrypt. It takes the DNS challenge time and creates a record in Route53 for
that challenge. This completes the Lets Encrypt challenge and we receive a
certificate. It uploads the new certificate and private key to IAM and updates
your ELB to use the certificate.

In theory all you need to do is make sure this is running somewhere, and your
ELBs' certificates will be kept minty fresh.

How to run it
-------------

Before you can use ``letsencrypt-aws`` you need to have created an account with
the ACME server. Documentation for how to do this is outside the scope of
``letsencrypt-aws``. You'll need to put the private key somewhere that
``letsencrypt-aws`` can access it.

``letsencrypt-aws`` takes it's configuration via the ``LETSENCRYPT_AWS_CONFIG``
environment variables. This should be a JSON object with the following schema:

.. code-block:: json

    {
        "domains": [
            {
                "elb": {
                    "name": "ELB name",
                    "port": 443
                },
                "hosts": ["..."]
            }
        ],
        "acme_account_key": "location of the account private key",
        "acme_directory_url": "optional, can be used to test with staging"
    }

The ``acme_account_key`` can either be located on the local filesystem or in
S3. To specify a local file you provide ``"file:///path/to/key.pem"``, for S3
provide ``"s3://bucket-nam/object-name"``.

Then you can simply run it: ``python letsencrypt-aws.py``.

If you add the ``--persistent`` flag it will run forever, rather than just
once. This is useful for production environments.
