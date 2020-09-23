#!/usr/bin/python3 -u

import sys
import os
import yaml
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta


def print_info(message):
    print("\033[1mINFO:\033[0m", message)


def print_warn(message):
    print("\033[93m\033[1mWARN:\033[0m", message, file=sys.stderr)


def print_error(message):
    print("\033[91m\033[1mFAIL:\033[0m", message, file=sys.stderr)


class GeneratorError(Exception):
    pass


class CaGenerator:

    def __init__(self, args):
        self.output = args['output']
        self.vault_id = args['vault_id']

        self.expiry = args['expiry']
        self.path_len = args['path-len']
        self.key_size = args['key-size']

        self.common_name = args['common-name']
        self.country = args['country']
        self.state_or_province = args['state-or-province']
        self.locality = args['locality']
        self.organization = args['organization']
        self.organizational_unit = args['organizational-unit']

        if self.path_len is None or self.path_len <= 0:
            if self.path_len:
                print_warn("invalid path-len: %d, must be > 0, setting it to 1" % self.path_len)
            self.path_len = 1

        self.default_expiry = args['default-expiry']

        if self.expiry is None or self.expiry <= 0:
            if self.expiry is not None:
                print_warn("invalid expiry: %d, must be > 0, setting it to 10y" % self.expiry)
            self.expiry = 10 * 365 * 24

        if not self.key_size:
            self.key_size = 4096

        if self.default_expiry is None or self.default_expiry <= 0:
            if self.default_expiry is not None:
                print_warn("invalid default-expiry: %d, must be > 0, setting it to 5y" % self.default_expiry)
            self.default_expiry = 5 * 365 * 24

    def generate_profiles(self):
        expiry_hours = "+%dh" % self.default_expiry
        return {
            'server': {
                'expiry': expiry_hours,
                'valid_at': '+720h',
                'key_usage': [
                    "digitalSignature",
                    "keyEncipherment",
                ],
                'key_usage_critical': True,
                'extended_key_usage': [
                    "serverAuth",
                ],
                'extended_key_usage_critical': True,
                'san_critical': False
            },
            "peer": {
                'expiry': expiry_hours,
                'valid_at': '+720h',
                'key_usage': [
                    "digitalSignature",
                    "keyEncipherment",
                ],
                'key_usage_critical': True,
                'extended_key_usage': [
                    "serverAuth",
                    "clientAuth",
                ],
                'extended_key_usage_critical': True,
                'san_critical': False
            },
            "client": {
                'expiry': expiry_hours,
                'valid_at': '+720h',
                'key_usage': [
                    "digitalSignature",
                    "keyEncipherment",
                ],
                'key_usage_critical': True,
                'extended_key_usage': [
                    "clientAuth",
                ],
                'extended_key_usage_critical': True,
                'san_critical': False
            }
        }

    def gen_ca_cert(self):
        print_info("Generating private key...")

        # TODO: support different algorithms
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )

        print_info("Building certificate...")
        builder = x509.CertificateBuilder()

        subject_mapping = {
            NameOID.COMMON_NAME: self.common_name,
            NameOID.COUNTRY_NAME: self.country,
            NameOID.STATE_OR_PROVINCE_NAME: self.state_or_province,
            NameOID.LOCALITY_NAME: self.locality,
            NameOID.ORGANIZATION_NAME: self.organization,
            NameOID.ORGANIZATIONAL_UNIT_NAME: self.organizational_unit,
        }

        subject = []

        for name, value in subject_mapping.items():
            if value is None:
                continue

            if isinstance(value, list):
                for v in value:
                    subject.append(x509.NameAttribute(name, v))
            else:
                subject.append(x509.NameAttribute(name, value))

        builder = builder.subject_name(x509.Name(subject))
        builder = builder.issuer_name(x509.Name(subject))

        builder = builder.not_valid_before(datetime.today() - timedelta(hours=1))
        builder = builder.not_valid_after(datetime.today() + timedelta(hours=self.expiry) - timedelta(hours=1))

        builder = builder.serial_number(x509.random_serial_number())

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=self.path_len), critical=True,
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ), critical=True
        )

        builder = builder.public_key(private_key.public_key())

        print_info("Signing certificate...")
        certificate = builder.sign(
            private_key=private_key,
            algorithm=hashes.SHA512(),
            backend=default_backend()
        )

        ret = {
            "private_key": private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode("utf-8"),

            "certificate": certificate.public_bytes(
                encoding=serialization.Encoding.PEM,
            ).decode("utf-8")
        }

        print_info("Certificate created")

        return ret

    def dump_yaml(self, ca):
        class literal(str):
            pass

        def literal_presenter(dumper, data):
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')

        yaml.add_representer(literal, literal_presenter)

        vault_data = {
            "certificate": literal(ca["certificate"]),
            "private_key": literal(ca["private_key"]),
            "profiles": ca["profiles"],
            "valid_at": "+720h",
        }

        return yaml.dump(vault_data, default_flow_style=False, explicit_start=True, encoding='utf8')

    def generate(self):
        try:
            if self.output != "-" and os.path.isfile(self.output):
                print_error("File {0} already exists".format(self.output))
                return 1
            
            ca = self.gen_ca_cert()
            ca["profiles"] = self.generate_profiles()

            data = self.dump_yaml(ca)

            if self.vault_id:
                print_info("running ansible-vault...")
                print("***** ansible-vault *****")

                cmd = ["ansible-vault", "encrypt", "--output", "-"]
                
                if isinstance(self.vault_id, str):
                    cmd.append("--vault-id")
                    cmd.append(self.vault_id)

                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
                p.stdin.write(data)
                p.stdin.close()
                data = p.stdout.read().decode("utf-8")
                ret = p.wait()
                p.stdout.close()
                print("***** ansible-vault *****")
                
                if ret:
                    raise GeneratorError("ansible-vault returned: %d" % ret)
                print_info("ansible-vault returned: OK\n")
                
            else:
                data = data.decode("utf-8")

            if self.output == "-":
                sys.stdout.write(data)
            else:
                with open(self.output, "w") as f:
                    f.write(data)

        except GeneratorError as e:
            print_error(e)
            return 1

        return 0


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="CA generator for mgssl action plugin")
    parser.add_argument('--output', '-o', dest='output', required=True,
                        help='output filename, use \'-\' for stdout')
    parser.add_argument('--ansible-vault', '-V', nargs='?', const=True, dest='vault_id',
                        help='encrypt output via ansible vault')

    parser.add_argument('--expiry', '-e', dest='expiry', type=int,
                        help='the expiration time for CA in hours (default: 87600 -> 10y).')
    parser.add_argument('--path-len', dest='path-len', type=int,
                        help='the maximum path length to set for the certificate chain.')
    parser.add_argument('--key-size', dest='key-size', type=int,
                        help='the key size to use (default: 2048)')

    parser.add_argument('--common-name', '-CN', dest='common-name', required=True,
                        help='the common-name to be used for CA Subject')
    parser.add_argument('--country', '-C', dest='country',
                        help='the country name to be used for CA Subject')
    parser.add_argument('--state-or-province', '-ST', dest='state-or-province',
                        help='the state or province to be used for CA Subject')
    parser.add_argument('--locality', '-L', dest='locality',
                        help='the locality name to be used for CA Subject')
    parser.add_argument('--organization', '-O', dest='organization',
                        help='the organization name to be used for CA Subject')
    parser.add_argument('--organizational-unit', '-OU', dest='organizational-unit',
                        help='the organizationional unit name to be used for CA Subject', action='append')

    parser.add_argument('--default-expiry', type=int, dest='default-expiry',
                        help='the default expiration time in hours to be used when generating profiles (default: 43800 -> 10y).'
                             'This will only be used for certificates signed by this CA. See --expiry for expiration of the CA itself.')

    knownArgs = parser.parse_args()

    caGen = CaGenerator(vars(knownArgs))
    sys.exit(caGen.generate())
