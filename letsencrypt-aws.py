import datetime
import json
import os
import time
import uuid

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import boto3


CERTIFICATE_EXPIRATION_THRESHOLD = datetime.timedelta(days=45)


def generate_csr(private_key, hosts):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        # TODO
        x509.Name([])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(host)
            for host in hosts
        ]),
        critical=True
    )
    return csr_builder.sign(private_key, hashes.SHA256(), default_backend())


def update_elb(elb_client, iam_client, elb_name, elb_port, hosts):
    response = elb_client.describe_load_balancers(
        LoadBalancerNames=[elb_name]
    )
    [description] = response["LoadBalancerDescriptions"]
    certificate_ids = [
        listener["Listener"]["SSLCertificateId"]
        for listener in description["ListenerDescriptions"]
        if listener["Listener"]["LoadBalancerPort"] == elb_port
    ]

    assert len(certificate_ids) <= 1
    if len(certificate_ids) == 1:
        response = iam_client.get_server_certificate(
            ServerCertificateName=certificate_ids[0]
        )
        metadata = response["ServerCertificate"]["ServerCertificateMetadata"]
        days_to_expiration = metadata["Expiration"] - datetime.date.today()
        needs_update = days_to_expiration < CERTIFICATE_EXPIRATION_THRESHOLD
    else:
        needs_update = True

    if not needs_update:
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    csr = generate_csr(private_key, hosts)

    # TODO:
    # 1) Make a request to Lets Encrypt
    # 2) Add record to Route53
    # 3) Do whatever else needs to happen with Lets Encrypt to
    #    acquire certificate
    # 4) Delete the Route53 record

    response = iam_client.upload_server_certificate(
        # TODO: is there some naming convention we should use?
        ServerCertificateName=str(uuid.uuid4()),
        PrivateKey=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        CertificateBody=pem_certificate,
        CertificateChain=pem_certificate_chain,
    )
    new_cert_arn = response["ServerCertificateMetadata"]["Arn"]

    elb_client.set_load_balancer_listener_ssl_certificate(
        LoadBalancerName=elb_name,
        SSLCertificateId=new_cert_arn,
        LoadBalancerPort=elb_port,
    )

    # TODO: Delete the old certificate?


def main():
    session = boto3.Session()
    elb_client = session.client("elb")
    iam_client = session.client("iam")
    # Structure: {
    #     "domains": [
    #         {"elb": {"name" "...", "port" 443}, hosts: ["..."]}
    #     ]
    # }
    domains = json.loads(os.environ["LETSENCRYPT_AWS_CONFIG"])
    while True:
        for domain in domains:
            update_elb(
                elb_client,
                iam_client,
                domain["elb"]["name"],
                domain["elb"]["port"],
                domain["hosts"]
            )
        # Sleep a day before we check again
        time.sleep(60 * 60 * 24)


if __name__ == "__main__":
    main()
