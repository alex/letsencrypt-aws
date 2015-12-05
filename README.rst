letsencrypt-aws
===============

**This is currently in development. It doesn't work.**

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
