# Ansible Collection - mgit_at.mgssl

This plugin helps to generate server and client certificates from an existing CA in a secure manner. The CA Key is never exposed to the remote host. The generation of the certicates happen on the localhost.

The collection includes following plugins:

- certificate

For details of the usage please referre to [Example Usage](##example-usage)

## Table of contents

1. [Installation](##installation)
2. [Requirements](##requirements)
3. [Plugin Options](##plugin-options)
4. [Dependencies](##dependencies)
5. [Example Usage](##example-usage)
   1. [CA Config Example](###ca-config-example)
6. [Generate a CA](##generate-a-ca)
7. [License](##license)
8. [Author Information](##author-information)

## Installation

To install from ansible galaxy:

    ansible-galaxy collection install mgit_at.mgssl

**Currently not working as we are waiting for the orgranisation group on ansible galaxy**

To install from github directly:

    ansible-galaxy collection install -r requirements.yml -f

The requirements.yml needs to have the following format and content:

    ---
    collections:
        - https://github.com/mgit-at/ansible-collection-mgssl/releases/download/v<version>/mgit_at-mgssl-<version>.tar.gz

Hint: Replace the version with the version you will need .
## Requirements

This plugin is compatible with 2.8 <= ansible <= 2.9. In 2.8 the new openssl module was introducted, which is used by this role.

**Ansible Version 2.10 is not compatible with this module yet. As there are many major changes in it**

The below requirements are needed on the host that executes this module.

- PyOpenSSL >= 0.15 or cryptography >= 1.6
- OpenSSL binary in $PATH (only on CA Host)

## Plugin Options

This section gives an overview off all the plugin options of mgit.mgssl.certificate

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
        type: list


## Dependencies

None.

## Example Usage

Minium required options to generate a certificate:

    - name: Minimum required options to generate a certificate
      mgit.mgssl.certificate:
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
      mgit.mgssl.certificate:
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
      mgit.mgssl.certificate:
        subject:
          CN: "Example certificate"
        ca_config_path: "config.yml"
        profile: client
        private_key_path: "/cert.key"
        cert_path: "/cert.pem"
        enable_cert_creation: True


Use a existing CA to generate a certificate:

    - name: Load CA certificate and private key from file
      mgit.mgssl.certificate:
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
      mgit.mgssl.certificate:
        subject:
          CN: "Example certificate"
        ca_config_path: "config.yml"
        profile: client
        private_key_path: "/cert.key"
        cert_path: "/cert.pem"
        enable_cert_creation: True
        force: True

You can also use the ``profiles`` option to define the certificate profile inline:

    - name: Define profile inline
      mgit.mgssl.certificate:
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

To set a SANs use the ``SANs`` option:

    - name: Generate a certificate with SANs
      mgit.mgssl.certificate:
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

To ignore expired certificates you can set the ``assert`` option:

    - name: Disable assertions
      mgit.mgssl.certificate:
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

This file show an example CA config. Note that the CA Key is also included. To be secure encrypt the whole config or the key variable with vault.

    ---
    certificate: |
      -----BEGIN CERTIFICATE-----
      -----END CERTIFICATE-----
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
        extended_key_usage_critical: False
        san_critical: False
      peer:
        expiry: +43800h
        valid_at: +720h
        key_usage:
        - digitalSignature
        - keyEncipherment
        key_usage_critical: True
        extended_key_usage:
        - clientAuth
        - serverAuth
        extended_key_usage_critical: False
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
        extended_key_usage_critical: False
        san_critical: False
    private_key: |
      -----BEGIN RSA PRIVATE KEY-----
      -----END RSA PRIVATE KEY-----

## Generate a CA

The contrib folder includes a the python script ``generate-ca.py``. This file can be used to generate a CA.

    usage: generate-ca.py [-h] --output OUTPUT [--ansible-vault [VAULT_ID]] [--expiry EXPIRY] [--path-len PATH-LEN] [--key-size KEY-SIZE] --common-name COMMON-NAME [--country COUNTRY]
                      [--state-or-province STATE-OR-PROVINCE] [--locality LOCALITY] [--organization ORGANIZATION] [--organizational-unit ORGANIZATIONAL-UNIT]
                      [--default-expiry DEFAULT-EXPIRY]


## License

Apache-2.0 License

## Author Information

This collection was created in 2020 by Patrick Pichler ([@aveexy](https://github.com/aveexy)) and Jonas Reindl ([@ohdearaugustin](https://github.com/ohdearaugustin)) from [Mgit GmbH](https://mgit.at).
