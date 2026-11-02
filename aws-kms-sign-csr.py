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

# OIDs from NIST CSOR / draft-ietf-lamps-dilithium-certificates
ML_DSA_SIGNATURE_OIDS = {
    'ML_DSA_44': '2.16.840.1.101.3.4.3.17',
    'ML_DSA_65': '2.16.840.1.101.3.4.3.18',
    'ML_DSA_87': '2.16.840.1.101.3.4.3.19',
}


def sign_certification_request_info(kms, key_id, csr, digest_algorithm, signing_algorithm):
    certificationRequestInfo = csr['certificationRequestInfo']
    der_bytes = encoder.encode(certificationRequestInfo)
    digest = hashlib.new(digest_algorithm)
    digest.update(der_bytes)
    digest = digest.digest()
    response = kms.sign(KeyId=key_id, Message=digest, MessageType='DIGEST', SigningAlgorithm=signing_algorithm)
    return response['Signature']


def compute_external_mu(message_bytes, public_key_octets):
    # FIPS 204 section 6.2, with an empty context string (as used by AWS KMS's
    # EXTERNAL_MU examples): mu = SHAKE256(SHAKE256(pk, 64) || 0x00 || 0x00 || M, 64)
    tr = hashlib.shake_256(public_key_octets).digest(64)
    prefix = bytes([0, 0])  # domain separator (0) || context length (0, empty context)
    return hashlib.shake_256(tr + prefix + message_bytes).digest(64)


def sign_certification_request_info_mldsa(kms, key_id, csr, public_key_octets):
    certificationRequestInfo = csr['certificationRequestInfo']
    der_bytes = encoder.encode(certificationRequestInfo)
    mu = compute_external_mu(der_bytes, public_key_octets)
    response = kms.sign(KeyId=key_id, Message=mu, MessageType='EXTERNAL_MU',
                        SigningAlgorithm='ML_DSA_SHAKE_256')
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
    pubkey_info = decoder.decode(pubkey_der, pyasn1_modules.rfc2314.SubjectPublicKeyInfo())[0]
    csr['certificationRequestInfo']['subjectPKInfo'] = pubkey_info

    if args.signalgo == 'ML-DSA':
        public_key_octets = pubkey_info['subjectPublicKey'].asOctets()
        signatureBytes = sign_certification_request_info_mldsa(kms, args.keyid, csr, public_key_octets)
        sigAlgOid = ML_DSA_SIGNATURE_OIDS[response['KeySpec']]
    else:
        signatureBytes = sign_certification_request_info(kms, args.keyid, csr, args.hashalgo,
                                                         signing_algorithm(args.hashalgo, args.signalgo)[0])
        sigAlgOid = signing_algorithm(args.hashalgo, args.signalgo)[1]

    csr.setComponentByName('signature', univ.BitString.fromOctetString(signatureBytes))

    sigAlgIdentifier = pyasn1_modules.rfc2314.SignatureAlgorithmIdentifier()
    sigAlgIdentifier.setComponentByName('algorithm', univ.ObjectIdentifier(sigAlgOid))
    csr.setComponentByName('signatureAlgorithm', sigAlgIdentifier)

    output_csr(csr)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('csr', help="Source CSR (can be signed with any key)")
    parser.add_argument('--keyid', action='store', dest='keyid', help='key ID in AWS KMS')
    parser.add_argument('--region', action='store', dest='region', help='AWS region')
    parser.add_argument('--profile', action='store', dest='profile', help='AWS profile')
    parser.add_argument('--hashalgo', choices=['sha224', 'sha256', 'sha512', 'sha384'], default="sha256",
                        help='hash algorithm to choose (ignored for --signalgo ML-DSA)')
    parser.add_argument('--signalgo', choices=['ECDSA', 'RSA', 'ML-DSA'], default="RSA",
                        help='signing algorithm to choose')
    args = parser.parse_args()
    main(args)
