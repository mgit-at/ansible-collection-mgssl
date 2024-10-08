#!/usr/bin/python

# Copyright: (c) 2019, Patrick Pichler <ppichler+ansible@mgit.at>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt


from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1'}

DOCUMENTATION = r'''
---
module: certificate
short_description: Creates a certificate signed by a ca and tests validity of certificate
description:
    - Checks if a certificate exists and matches the given constraints
    - Is no certificate exists or the check failed, a new certificate gets generated
requirements:
    - PyOpenSSL >= 0.15 or cryptography >= 1.6
    - OpenSSL binary in $PATH (only on C(ca_host))
author:
    - Patrick Pichler (@aveexy)
    - Jonas Reindl (@ohdearaugustin)
options:
    select_crypto_backend:
        description: Determines which crypto backend to use.
        type: str
        default: auto
        choices: [ auto, cryptography, pyopenssl ]

    ca_host:
        description: Host on which the certification signing should happen
        default: 127.0.0.1

    ca_host_options:
        description: Options that should be passed to tasks running on the ca host
        type: dict

    enable_cert_creation:
        description: Enable certificate creation
        type: bool
        default: False

    force:
        description: Always generate the certificate
        type: bool
        default: False

    private_key_path:
        description: Remote path to the certificate key file
        type: path
        required: True

    cert_path:
        description: Remote path to the certificate file
        type: path
        required: True

    ca_cert_path:
        description: Remote path to the ca certificate file
        type: path

    fullchain_cert_path:
        description: Remote path to the full chain certificate file
        type: path

    archive_dir_path:
        description:
            - Path on ca_host to the certificate archive directory
            - File name is the serial number of the certificate
        type: path

    archive_path:
        description: Path on ca_host to the certificate file
        type: path

    ca_config_path:
        description: Path to the ca configuration file which gets generated by the 'generate-ca.py' script
        type: path

    private_key_length:
        description: private key length
        type: str
        default: "4096"

    private_key_type:
        description: Remote private key type
        type: str
        default: RSA

    cert_mode:
        description: Remote certificate file mode
        default: 0o600

    private_key_mode:
        description: Private key file mode
        default: 0o600

    ca:
        description: CA Certificate options
        suboptions:
            certificate:
                description: Certificate in string form
                type: str

            private_key:
                description: Private key in string form
                type: str

            certificate_path:
                description: Path on ca_host to ca certificate file
                type: path

            private_key_path:
                description: Path on ca_host to ca private key file
                type: path

            valid_at:
                description: CA valid_at assertion
                default: +720h

    assert:
        description: Enable/disable assertions
        suboptions:
            signature_algorithm:
                description: Allowed signature algorithms
                type: list
                elements: str
                default: [ sha256WithRSAEncryption, sha384WithRSAEncryption, sha512WithRSAEncryption,
                         sha256WithECDSAEncryption, sha384WithECDSAEncryption, sha512WithECDSAEncryption ]
            subject:
                description: Enable/disable subject assertion
                type: bool
                default: True

            issuer:
                description: Enable/disable issuer assertion
                type: bool
                default: True

            expired:
                description: Enable/disable expired assertion
                type: bool
                default: True

            version:
                description: x509 version assertion
                default: 3

            key_usage:
                description: Enable/disable key usage assertion
                type: bool
                default: True

            key_usage_critical:
                description: Enable/disable key usage critical assertion
                type: bool
                default: True

            extended_key_usage:
                description: Enable/disable extended key usage assertion
                type: bool
                default: True

            extended_key_usage_critical:
                description: Enable/disable extended key usage critical assertion
                type: bool
                default: True

            san:
                description: Enable/disable san assertion
                type: bool
                default: True

            san_critical:
                description: Enable/disable san critical assertion
                type: bool
                default: True

            valid_at:
                description: Enable/disable valid_at assertion
                type: bool
                default: True

            ca_expired:
                description: Enable/disable ca expired assertion
                type: bool
                default: True

            ca_valid_at:
                description: Enable/disable ca valid_at assertion
                type: bool
                default: True

    profile:
        description: Select profile in profiles list
        type: str
        required: true

    profiles:
        description:
            - Profiles define various parameters required for the certificate generation
            - When C(ca_config_path) is set and contains profiles they get merged, preferring the ca config profiles
        suboptions:
            expiry:
                description:
                    - Certificate expiry
                    - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
                      + C([w | d | h | m | s])

            valid_at:
                description:
                    - Point in time where the certificate is required to be valid
                    - Valid format is C([+-]timespec | ASN.1 TIME) where timespec can be an integer
                      + C([w | d | h | m | s])

            key_usage:
                description:
                    - Certificate key usages
                    - "Possible options:"
                    - digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
                    - keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly
                elements: str
                type: list

            key_usage_critical:
                description: Certificate key usage critical flag
                type: bool

            extended_key_usage:
                description: Certificate extended key usages
                elements: str
                type: list

            extended_key_usage_critical:
                description: Certificate extended key usage critical flag
                type: bool

            san_critical:
                description: Certificate san critical flag
                type: bool
        default: _default

    subject:
        description: Subject of certificate
        required: yes
        suboptions:
            commonName:
                description: Common name
                aliases:
                    - CN

            countryName:
                description: Country name
                aliases:
                    - C

            stateOrProvinceName:
                description: State or province name
                aliases:
                    - ST

            localityName:
                description: Locality name
                aliases:
                    - L

            organizationName:
                description: Organization name
                aliases:
                    - O

            organizationalUnitName:
                description: Organizational unit name
                aliases:
                    - OU

            emailAddress:
                description: E-Mail Address

    SANs:
        description:
            - List of SANs
            - "Values must be prefixed with type name 'TYPE:value'. Example 'DNS:example.com'"
            - "Valid types: DNS, IP, email, URI"
        elements: str
        type: list

'''

EXAMPLES = r'''
- name: Minimum required options to generate a certificate
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca:
      certificate: |
          -----BEGIN CERTIFICATE-----
          ...
      private_key: |
          -----BEGIN RSA PRIVATE KEY-----
          ...
      valid_at: "+720h"
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True

- name: Use ca config file
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca_config_path: "config.yml"
    profile: client
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True

- name: Load CA certificate and private key from file
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca:
      certificate_path: "/ca.pem"
      private_key_path: "/ca.key"
      valid_at: "+720h"
    profile: client
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True

- name: Force certificate generation
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca_config_path: "config.yml"
    profile: client
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True
    force: True

- name: Define profile inline
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca_config_path: "config.yml"
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True
    profile: server
    profiles:
      server:
        expiry: "+43800h"
        valid_at: '+720h'
        key_usage:
          - keyEncipherment
          - digitalSignature
        key_usage_critical: True
        extended_key_usage:
          - serverAuth
        extended_key_usage_critical: True
        san_critical: False

- name: Generate a certificate with SANs
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca_config_path: "config.yml"
    profile: client
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True
    SANs:
      - "DNS:example.com"
      - "DNS:www.example.com"
      - "IP:127.0.0.1"

- name: Disable assertions
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca_config_path: "config.yml"
    profile: client
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True
    assert:
      # Ignore expired certificate
      valid_at: null
      expired: null

- name: Include CA and fullchain certificates
  mgit_at.mgssl.certificate:
    subject:
      CN: "Example certificate"
    ca_config_path: "config.yml"
    profile: client
    private_key_path: "/cert.key"
    cert_path: "/cert.pem"
    enable_cert_creation: True
    ca_cert_path: "/ca.pem"
    fullchain_cert_path: "/cert_fullchain.pem"
'''
