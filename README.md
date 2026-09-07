# Ansible Collection - mgit_at.mgssl

This plugin helps to generate server and client certificates from an existing CA in a secure manner. The CA key is never exposed to the remote host: the private key and the signing
request are created on the target host, and only the signing itself happens on the CA host, which defaults to `127.0.0.1` (the control node) and can be changed with `ca_host`.

The collection includes following plugins:

- certificate

For details of the usage please refer to [Example Usage](#example-usage)

## Table of contents

1. [Installation](#installation)
2. [Requirements](#requirements)
3. [Plugin Options](#plugin-options)
4. [Dependencies](#dependencies)
5. [Example Usage](#example-usage)
   1. [CA Config Example](#ca-config-example)
6. [Generate a CA](#generate-a-ca)
7. [License](#license)
8. [Author Information](#author-information)

## Installation

To install from ansible galaxy:

    ansible-galaxy collection install mgit_at.mgssl

To install from github directly:

    ansible-galaxy collection install -r requirements.yml -f

The requirements.yml needs to have the following format and content:

    ---
    collections:
        - https://github.com/mgit-at/ansible-collection-mgssl/releases/download/v<version>/mgit_at-mgssl-<version>.tar.gz

Hint: Replace the version with the version you will need .

## Requirements

### Collection 2.x (current)

The [Community Crypto Collection](https://galaxy.ansible.com/community/crypto) is needed to use this collection.

Installation:

    ansible-galaxy collection install community.crypto

**Supported ansible-core versions: 2.19.x, 2.20.x and 2.21.x**

These are the three ansible-core releases that upstream still maintains. 2.18 reached its end of life in May 2026, 2.17 in November 2025 and 2.16 in July 2025. The collection
tracks that window rather than defining its own: every push runs the sanity suite against all three, and the integration suite against each of them on two Python versions.
When upstream drops a release, the next release of this collection drops it too.

| ansible-core | Status                   | Control node Python |
| ------------ | ------------------------ | ------------------- |
| 2.21.x       | supported, tested in CI  | 3.12 - 3.14         |
| 2.20.x       | supported, tested in CI  | 3.12 - 3.14         |
| 2.19.x       | supported, tested in CI  | 3.11 - 3.13         |
| 2.16 - 2.18  | untested, likely to work | 3.10 / 3.11 and up  |
| 2.10 - 2.15  | not supported            | -                   |
| < 2.10       | does not work            | -                   |

Versions 2.16 to 2.18 are only *likely* to work: the plugin still carries the code paths they need and nothing has deliberately been broken for them, but they left the CI
matrix when they went end of life, so regressions there will not be caught. Versions 2.10 to 2.15 are too old to be worth supporting, and anything before 2.10 cannot work
at all because using other collections is not possible there.

The reason support is tied this closely to the ansible-core version is that the certificate action plugin drives the certificate generation on the CA host by instantiating
ansible-core's `TaskExecutor` directly. That is an internal API which has changed several times, so the plugin inspects its signature at runtime and picks the matching call:

| ansible-core | What changed                                                                                                 |
| ------------ | ------------------------------------------------------------------------------------------------------------ |
| 2.21+        | `task` and `job_vars` moved into a `TaskContext`, and `run()` returns a `UnifiedTaskResult` instead of a dict |
| 2.19 - 2.20  | `new_stdin` removed from the constructor                                                                     |
| 2.16 - 2.18  | constructor still takes `new_stdin`                                                                          |
| 2.9 - 2.15   | no `variable_manager` argument                                                                               |

If an unknown signature is encountered, the plugin fails with an explicit error instead of silently misbehaving. A new ansible-core release can therefore require a new
release of this collection even when nothing else changed.

The below requirements are needed on the host that executes this module.

- Python >= 3.12 (for control node with ansible-core 2.20 and 2.21)
- Python >= 3.11 (for control node with ansible-core 2.19)
- PyOpenSSL >= 0.15 or cryptography >= 1.6
- OpenSSL binary in $PATH (only on CA Host)

### Collection 1.x (historical)

The 1.x series targeted Ansible 2.8 and 2.9, which is where the openssl modules this collection builds on were introduced. It predates the collection/`ansible-core` split and is no
longer maintained — the 2.x series described above replaced it and supports every ansible-core release from 2.10 onwards. Use 1.x only if you are stuck on Ansible 2.9.

## Plugin Options

This section gives an overview off all the plugin options of mgit_at.mgssl.certificate

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
        default: 4096

    private_key_type:
        description: Remote private key type
        type: str
        default: RSA

    private_key_curve:
        description:
            - Passed through to community.crypto.openssl_privatekey as 'curve'
            - Only sent when set, and only relevant for elliptic curve key types
        type: str

    cert_mode:
        description: Remote certificate file mode, also applied to ca_cert_path and fullchain_cert_path
        default: 0o644

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
                default: [ sha256WithRSAEncryption, sha384WithRSAEncryption, sha512WithRSAEncryption,
                         ecdsa-with-SHA256, ecdsa-with-SHA384, ecdsa-with-SHA512 ]
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

            remote_private_key:
                description:
                    - Enable/disable the check that the private key on the remote host belongs to the certificate
                    - Verified by signing a nonce on the remote host and validating the signature against the certificate
                type: bool
                default: True

    profile:
        description: Select profile in profiles list
        type: str
        default: _default

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
                type: list

            key_usage_critical:
                description: Certificate key usage critical flag
                type: bool

            extended_key_usage:
                description: Certificate extended key usages
                type: list

            extended_key_usage_critical:
                description: Certificate extended key usage critical flag
                type: bool

            san_critical:
                description: Certificate san critical flag
                type: bool
        default:
            _default:
                expiry: "+43800h"
                valid_at: "+720h"
                key_usage: []
                key_usage_critical: False
                extended_key_usage: []
                extended_key_usage_critical: False
                san_critical: False

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
        type: list

## Dependencies

None.

## Example Usage

Minium required options to generate a certificate:

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

To generate the certificate, ca and the fullchain on the host use:

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

Use a CA config file to create a certificate:

    - name: Use ca config file
      mgit_at.mgssl.certificate:
        subject:
          CN: "Example certificate"
        ca_config_path: "config.yml"
        profile: client
        private_key_path: "/cert.key"
        cert_path: "/cert.pem"
        enable_cert_creation: True

Use a existing CA to generate a certificate:

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

Force the task to always generate the certificate:

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

You can also use the `profiles` option to define the certificate profile inline:

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

To set a SANs use the `SANs` option:

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

To ignore expired certificates you can set the `assert` option:

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
          valid_at: null
          expired: null

### CA Config Example

This is an example CA config, matching what `generate-ca.py` writes. Note that the CA key is included as well, so encrypt either the whole file or the `private_key` value
with ansible-vault — `generate-ca.py --ansible-vault` does the former for you.

    ---
    certificate: |
      -----BEGIN CERTIFICATE-----
      -----END CERTIFICATE-----
    valid_at: '+720h'
    profiles:
      client:
        expiry: +43800h
        valid_at: +720h
        key_usage:
        - digitalSignature
        - keyEncipherment
        key_usage_critical: True
        extended_key_usage:
        - clientAuth
        extended_key_usage_critical: True
        san_critical: False
      peer:
        expiry: +43800h
        valid_at: +720h
        key_usage:
        - digitalSignature
        - keyEncipherment
        key_usage_critical: True
        extended_key_usage:
        - serverAuth
        - clientAuth
        extended_key_usage_critical: True
        san_critical: False
      server:
        expiry: +43800h
        valid_at: +720h
        key_usage:
        - digitalSignature
        - keyEncipherment
        key_usage_critical: True
        extended_key_usage:
        - serverAuth
        extended_key_usage_critical: True
        san_critical: False
    private_key: |
      -----BEGIN RSA PRIVATE KEY-----
      -----END RSA PRIVATE KEY-----

## Generate a CA

The contrib folder includes a the python script `generate-ca.py`. This file can be used to generate a CA.

    usage: generate-ca.py [-h] --output OUTPUT [--ansible-vault [VAULT_ID]] [--expiry EXPIRY] [--path-len PATH-LEN] [--key-size KEY-SIZE] --common-name COMMON-NAME [--country COUNTRY]
                      [--state-or-province STATE-OR-PROVINCE] [--locality LOCALITY] [--organization ORGANIZATION] [--organizational-unit ORGANIZATIONAL-UNIT]
                      [--default-expiry DEFAULT-EXPIRY]

## License

Apache-2.0 License

## Author Information

This collection was created in 2020 by Patrick Pichler ([@aveexy](https://github.com/aveexy)) and Jonas Reindl ([@ohdearaugustin](https://github.com/ohdearaugustin)) from [mgit GmbH](https://mgit.at).

Copyright 2020 mgIT GmbH.
