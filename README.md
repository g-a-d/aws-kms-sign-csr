# aws-kms-sign-csr

Given an existing CSR (in PEM format) and a keypair in AWS KMS, this script:
* updates the public key to the public key of the asymmetric keypair
* signs the CSR with the private key of the asymmetric keypair

## Why would I want to do this?

You may have a use-case where you're signing arbitrary data using KMS, but checking
this signature against a certificate (or, by extension, checking that the certificate
has been chained from a trusted root or intermediate).

This script allows you to generate a CSR which uses the private key in KMS, which
can then be signed by your PKI. From here you can sign your arbitrary data using
KMS and you've maintained the security of your private key, as it has never left
KMS.

Note that this does NOT sign the CSR with a CA to make it into a bona fide certificate:
a CSR is signed with the private key of the generator so that the CA can ensure
that the public key is owned by the person who is requesting the certificate, and
this script re-signs with the private key held in KMS.

## Installation

    # create a new virtualenv 
    python3 -m venv aws-kms-sign-csr
    . aws-kms-sign-csr/bin/activate
    # install prerequisite modules
    pip3 install -r requirements.txt

## Usage

    # generate a PEM csr - the key doesn't matter as it will be replaced
    openssl req -new -newkey rsa:2048 -keyout /dev/null -nodes -out test.csr
    ./aws-kms-sign-csr.py --region eu-west-1 --keyid alias/mykeyalias --hashalgo sha256 test.csr > new.csr

The script will use your existing AWS credentials: to override use environment variables per https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html

The key ID can be a key ARN, an actual key ID, a key alias (prefixed with alias/), or a key alias ARN. See https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/kms.html#KMS.Client.sign for more info.

## Limitations

* only supports sha256, sha384 and sha512 at time of writing
* should have better error handling
* should have better handling of boto profiles
