#!/usr/bin/env python3
"""
python script to re-sign an existing CSR with an asymmetric keypair held in AWS KMS
"""

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ
import pyasn1_modules.pem
import pyasn1_modules.rfc2986
import pyasn1_modules.rfc2314
import hashlib
import base64
import textwrap
import argparse
import boto3

start_marker = '-----BEGIN CERTIFICATE REQUEST-----'
end_marker = '-----END CERTIFICATE REQUEST-----'


def sign_certification_request_info(kms, key_id, csr, digest_algorithm, signing_algorithm):
    certificationRequestInfo = csr['certificationRequestInfo']
    der_bytes = encoder.encode(certificationRequestInfo)
    digest = hashlib.new(digest_algorithm)
    digest.update(der_bytes)
    digest = digest.digest()
    response = kms.sign(KeyId=key_id, Message=digest, MessageType='DIGEST', SigningAlgorithm=signing_algorithm)
    return response['Signature']


def output_csr(csr):
    print(start_marker)
    b64 = base64.b64encode(encoder.encode(csr)).decode('ascii')
    for line in textwrap.wrap(b64, width=64):
        print(line)
    print(end_marker)


def signing_algorithm(hashalgo, signalgo):
    # Signature Algorithm OIDs retrieved from
    # https://www.ibm.com/docs/en/linux-on-systems?topic=linuxonibm/com.ibm.linux.z.wskc.doc/wskc_pka_pim_restrictions.html
    if hashalgo == 'sha512' and signalgo == 'ECDSA':
        return 'ECDSA_SHA_512', '1.2.840.10045.4.3.4'
    elif hashalgo == 'sha384' and signalgo == 'ECDSA':
        return 'ECDSA_SHA_384', '1.2.840.10045.4.3.3'
    elif hashalgo == 'sha256' and signalgo == 'ECDSA':
        return 'ECDSA_SHA_256', '1.2.840.10045.4.3.2'
    elif hashalgo == 'sha224' and signalgo == 'ECDSA':
        return 'ECDSA_SHA_224', '1.2.840.10045.4.3.1'
    elif hashalgo == 'sha512' and signalgo == 'RSA':
        return 'RSASSA_PKCS1_V1_5_SHA_512', '1.2.840.113549.1.1.13'
    elif hashalgo == 'sha384' and signalgo == 'RSA':
        return 'RSASSA_PKCS1_V1_5_SHA_384', '1.2.840.113549.1.1.12'
    elif hashalgo == 'sha256' and signalgo == 'RSA':
        return 'RSASSA_PKCS1_V1_5_SHA_256', '1.2.840.113549.1.1.11'
    else:
        raise Exception('unknown hash algorithm, please specify one of sha224, sha256, sha384, or sha512')


def main(args):
    with open(args.csr, 'r') as f:
        substrate = pyasn1_modules.pem.readPemFromFile(f, startMarker=start_marker, endMarker=end_marker)
        csr = decoder.decode(substrate, asn1Spec=pyasn1_modules.rfc2986.CertificationRequest())[0]
        if not csr:
            raise Exception('file does not look like a CSR')

    # now get the key
    if not args.region:
        args.region = boto3.session.Session().region_name

    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)
    kms = boto3.client('kms', region_name=args.region)

    response = kms.get_public_key(KeyId=args.keyid)
    pubkey_der = response['PublicKey']
    csr['certificationRequestInfo']['subjectPKInfo'] = \
        decoder.decode(pubkey_der, pyasn1_modules.rfc2314.SubjectPublicKeyInfo())[0]

    signatureBytes = sign_certification_request_info(kms, args.keyid, csr, args.hashalgo,
                                                     signing_algorithm(args.hashalgo, args.signalgo)[0])
    csr.setComponentByName('signature', univ.BitString.fromOctetString(signatureBytes))

    sigAlgIdentifier = pyasn1_modules.rfc2314.SignatureAlgorithmIdentifier()
    sigAlgIdentifier.setComponentByName('algorithm',
                                        univ.ObjectIdentifier(signing_algorithm(args.hashalgo, args.signalgo)[1]))
    csr.setComponentByName('signatureAlgorithm', sigAlgIdentifier)

    output_csr(csr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('csr', help="Source CSR (can be signed with any key)")
    parser.add_argument('--keyid', action='store', dest='keyid', help='key ID in AWS KMS')
    parser.add_argument('--region', action='store', dest='region', help='AWS region')
    parser.add_argument('--profile', action='store', dest='profile', help='AWS profile')
    parser.add_argument('--hashalgo', choices=['sha224', 'sha256', 'sha512', 'sha384'], default="sha256",
                        help='hash algorithm to choose')
    parser.add_argument('--signalgo', choices=['ECDSA', 'RSA'], default="RSA", help='signing algorithm to choose')
    args = parser.parse_args()
    main(args)
