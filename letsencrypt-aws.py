import datetime
import json
import os
import sys
import time

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
PERSISTENT_SLEEP_INTERVAL = 60 * 60 * 24


class Logger(object):
    def __init__(self):
        self._out = sys.stdout

    def emit(self, event, **data):
        formatted_data = " ".join(
            "%s=%r" % (k, v) for k, v in data.iteritems()
        )
        self._out.write("{} [{}] {}\n".format(
            datetime.datetime.utcnow().replace(microsecond=0),
            event,
            formatted_data
        ))


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
    for combo in authz.body.resolved_combinations:
        if (
            len(combo) == 1 and
            isinstance(combo[0].chall, acme.challenges.DNS01)
        ):
            yield combo[0]


def find_zone_id_for_domain(route53_client, domain):
    for page in route53_client.get_paginator("list_hosted_zones").paginate():
        for zone in page["HostedZones"]:
            # This assumes that zones are returned sorted by specificity,
            # meaning they'd be in the following order:
            # ["foo.bar.baz.com", "bar.baz.com", "baz.com", "com"]
            if (
                domain.endswith(zone["Name"]) or
                (domain + ".").endswith(zone["Name"])
            ):
                return zone["Id"]


def create_txt_record(route53_client, zone_id, domain, value):
    response = route53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "CREATE",
                    "ResourceRecordSet": {
                        "Name": domain,
                        "Type": "TXT",
                        "TTL": 30,
                        "ResourceRecords": [
                            # For some reason TXT records need to be manually
                            # quoted.
                            {"Value": '"{}"'.format(value)}
                        ]
                    }
                }
            ]
        }
    )
    return response["ChangeInfo"]["Id"]


def wait_for_route53_change(route53_client, change_id):
    while True:
        response = route53_client.get_change(Id=change_id)
        if response["ChangeInfo"]["Status"] == "INSYNC":
            return
        time.sleep(5)


def delete_txt_record(route53_client, zone_id, domain):
    route53_client.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            "Changes": [
                {
                    "Action": "DELETE",
                    "ResourceRecordSet": {
                        "Name": domain,
                        "Type": "TXT",
                    }
                }
            ]
        }
    )


def generate_certificate_name(hosts, cert):
    return "{hosts}-{expiration}".format(
        hosts="-".join(h.replace(".", "_") for h in hosts),
        expiration=cert.not_valid_after.date(),
    )


def get_load_balancer_certificate(elb_client, elb_name, elb_port):
    response = elb_client.describe_load_balancers(
        LoadBalancerNames=[elb_name]
    )
    [description] = response["LoadBalancerDescriptions"]
    [certificate_id] = [
        listener["Listener"]["SSLCertificateId"]
        for listener in description["ListenerDescriptions"]
        if listener["Listener"]["LoadBalancerPort"] == elb_port
    ]
    return certificate_id


def get_expiration_date_for_certificate(iam_client, ssl_certificate_arn):
    paginator = iam_client.get_paginator("list_server_certificates").paginate()
    for page in paginator:
        for server_certificate in page["ServerCertificateMetadataList"]:
            if server_certificate["Arn"] == ssl_certificate_arn:
                return server_certificate["Expiration"]


def update_elb(logger, acme_client, elb_client, route53_client, iam_client,
               elb_name, elb_port, hosts):
    logger.emit("updating-elb", elb_name=elb_name)
    certificate_id = get_load_balancer_certificate(
        elb_client, elb_name, elb_port
    )

    expiration_date = get_expiration_date_for_certificate(
        iam_client, certificate_id
    ).date()
    logger.emit(
        "updating-elb.certificate-expiration",
        elb_name=elb_name, expiration_date=expiration_date
    )
    days_until_expiration = expiration_date - datetime.date.today()
    if days_until_expiration > CERTIFICATE_EXPIRATION_THRESHOLD:
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    csr = generate_csr(private_key, hosts)

    authorizations = []
    for host in hosts:
        logger.emit(
            "updating-elb.request-acme-challenge", elb_name=elb_name, host=host
        )
        authz = acme_client.request_domain_challenges(
            host, new_authz_uri=acme_client.directory.new_authz
        )
        authorizations.append((host, authz))

    created_records = []
    for host, authz in authorizations:
        [dns_challenge] = find_dns_challenge(authz)
        validation = dns_challenge.validation(acme_client.key)

        zone_id = find_zone_id_for_domain(route53_client, host)
        logger.emit(
            "updating-elb.create-txt-record", elb_name=elb_name, host=host
        )
        change_id = create_txt_record(
            route53_client,
            zone_id,
            dns_challenge.validation_domain_name(host),
            validation,
        )
        created_records.append((
            host,
            dns_challenge,
            change_id,
            zone_id,
        ))

    for host, dns_challenge, change_id, _ in created_records:
        logger.emit(
            "updating-elb.wait-for-route53", elb_name=elb_name, host=host
        )
        wait_for_route53_change(route53_client, change_id)

        response = dns_challenge.response(acme_client.key)

        logger.emit(
            "updating-elb.local-validation", elb_name=elb_name, host=host
        )
        verified = response.simple_verify(
            dns_challenge.chall, host, acme_client.key.public_key()
        )
        if not verified:
            raise ValueError("Failed verification")

        logger.emit(
            "updating-elb.answer-challenge", elb_name=elb_name, host=host
        )
        acme_client.answer_challenge(dns_challenge, response)

    logger.emit("updating-elb.request-cert", elb_name=elb_name)
    cert_response, _ = acme_client.poll_and_request_issuance(
        acme.jose.util.ComparableX509(
            OpenSSL.crypto.load_certificate_request(
                OpenSSL.crypto.FILETYPE_ASN1,
                csr.public_bytes(serialization.Encoding.DER),
            )
        ),
        authzrs=[authz for _, authz in authorizations],
    )
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_response.body
    )
    pem_certificate_chain = "\n".join(
        OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        for cert in acme_client.fetch_chain(cert_response)
    )

    logger.emit("updating-elb.upload-iam-certificate", elb_name=elb_name)
    response = iam_client.upload_server_certificate(
        ServerCertificateName=generate_certificate_name(
            hosts,
            x509.load_pem_x509_certificate(pem_certificate, default_backend())
        ),
        PrivateKey=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        CertificateBody=pem_certificate,
        CertificateChain=pem_certificate_chain,
    )
    new_cert_arn = response["ServerCertificateMetadata"]["Arn"]

    logger.emit("updating-elb.set-elb-certificate", elb_name=elb_name)
    elb_client.set_load_balancer_listener_ssl_certificate(
        LoadBalancerName=elb_name,
        SSLCertificateId=new_cert_arn,
        LoadBalancerPort=elb_port,
    )

    for host, dns_challenge, _, zone_id in created_records:
        logger.emit(
            "updating-elb.delete-txt-record", elb_name=elb_name, host=host
        )
        delete_txt_record(
            route53_client, zone_id, dns_challenge.validation_domain_name(host)
        )


def update_elbs(logger, acme_client, elb_client, route53_client, iam_client,
                domains):
    for domain in domains:
        update_elb(
            logger,
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
    logger = Logger()
    logger.emit("startup")

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
        logger.emit("running", mode="persistent")
        while True:
            update_elbs(
                logger, acme_client, elb_client, route53_client, iam_client,
                domains
            )
            # Sleep before we check again
            logger.emit("sleeping", duration=PERSISTENT_SLEEP_INTERVAL)
            time.sleep(PERSISTENT_SLEEP_INTERVAL)
    else:
        logger.emit("running", mode="single")
        update_elbs(
            logger, acme_client, elb_client, route53_client, iam_client,
            domains
        )


if __name__ == "__main__":
    main()
