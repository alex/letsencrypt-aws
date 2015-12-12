import datetime
import json
import os
import time
import uuid

import acme.challenges
import acme.client
import acme.jose

import click

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import boto3

import OpenSSL.crypto

import rfc3986


DEFAULT_ACME_DIRECTORY_URL = "https://acme-v01.api.letsencrypt.org/directory"
CERTIFICATE_EXPIRATION_THRESHOLD = datetime.timedelta(days=45)


def generate_csr(private_key, hosts):
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        # This is the same thing the official letsencrypt client does.
        x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, hosts[0]),
        ])
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(host)
            for host in hosts
        ]),
        critical=True
    )
    return csr_builder.sign(private_key, hashes.SHA256(), default_backend())


def find_dns_challenge(authz):
    for combo in authz.body.combinations:
        if (
            len(combo) == 1 and
            isinstance(authz.body.challenges[combo[0]], acme.challenges.DNS)
        ):
            yield authz.body.challenges[combo[0]]


def wait_for_route53_change(route53_client, change_id):
    while True:
        response = route53_client.get_change(Id=change_id)
        if response["ChangeInfo"]["Status"] == "INSYNC":
            return
        time.sleep(10)


def update_elb(acme_client, elb_client, route53_client, iam_client, elb_name,
               elb_port, hosts):
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

    authorizations = [
        (
            host,
            acme_client.request_domain_challenges(
                host, new_authz_uri=acme_client.directory.new_authz
            )
        )
        for host in hosts
    ]
    for host, authz in authorizations:
        [dns_challenge] = find_dns_challenge(authz)
        validation = dns_challenge.gen_validation()

        response = route53_client.change_resource_record_sets(
            # TODO: query route53 to get the HostedZoneId
            HostedZoneId='...',
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": dns_challenge.validation_domain_name(host),
                            "Type": "TXT",
                            "ResourceRecords": [
                                # TODO: is this serialized correctly?
                                {"Value": validation}
                            ]
                        }
                    }
                ]
            }
        )
        if response["ChangeInfo"]["Status"] != "INSYNC":
            # TODO: reorganize this code so that we can create all the changes
            # and then wait for them all, instead of serializing.
            wait_for_route53_change(
                route53_client, response["ChangeInfo"]["Id"]
            )

        response = dns_challenge.gen_response()
        acme_client.answer_challenge(dns_challenge, response)

    cert_response, _ = acme_client.poll_and_request_issuance(
        acme.jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1,
                csr.public_bytes(serialization.Encoding.DER),
            )
        ),
        authzrs=[authz for _, authz in authorizations]
    )
    pem_certificate = OpenSSL.crypto.dump_privatekey(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    )
    pem_certificate_chain = "\n".join(
        OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_PEM,
            cert
        )
        for cert in acme_client.fetch_chain(cert_response)
    )
    # TODO: delete Route53 records

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


def update_elbs(acme_client, elb_client, route53_client, iam_client, domains):
    for domain in domains:
        update_elb(
            acme_client,
            elb_client,
            route53_client,
            iam_client,
            domain["elb"]["name"],
            domain["elb"]["port"],
            domain["hosts"]
        )


def setup_acme_client(s3_client, acme_directory_url, acme_account_key):
    uri = rfc3986.urlparse(acme_account_key)
    if uri.scheme == "file":
        with open(uri.path) as f:
            key = f.read()
    elif uri.scheme == "s3":
        # uri.path includes a leading "/"
        response = s3_client.get_object(Bucket=uri.host, Key=uri.path[1:])
        key = response["Body"].read()
    else:
        raise ValueError("Invalid acme account key: %r" % acme_account_key)

    key = serialization.load_pem_private_key(
        key, password=None, backend=default_backend()
    )
    return acme.client.Client(
        acme_directory_url, key=acme.jose.JWKRSA(key=key)
    )


@click.command()
@click.option(
    "--persistent", is_flag=True, help="Runs in a loop, instead of just once."
)
def main(persistent=False):
    session = boto3.Session()
    s3_client = session.client("s3")
    elb_client = session.client("elb")
    route53_client = session.client("route53")
    iam_client = session.client("iam")
    # Structure: {
    #     "domains": [
    #         {"elb": {"name" "...", "port" 443}, hosts: ["..."]}
    #     ],
    #     "acme_account_key": "s3://bucket/object",
    #     "acme_directory_url": "(optional)"
    # }
    config = json.loads(os.environ["LETSENCRYPT_AWS_CONFIG"])
    domains = config["domains"]
    acme_directory_url = config.get(
        "acme_directory_url", DEFAULT_ACME_DIRECTORY_URL
    )
    acme_account_key = config["acme_account_key"]
    acme_client = setup_acme_client(
        s3_client, acme_directory_url, acme_account_key
    )

    if persistent:
        while True:
            update_elbs(
                acme_client, elb_client, route53_client, iam_client, domains
            )
            # Sleep a day before we check again
            time.sleep(60 * 60 * 24)
    else:
        update_elbs(
            acme_client, elb_client, route53_client, iam_client, domains
        )


if __name__ == "__main__":
    main()
