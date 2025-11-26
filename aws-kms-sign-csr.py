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


def sign_certification_request_info(kms, key_id, csr, digest_algorithm, signing_algorithm) -> bytes:
    """
    Sign a certification request info using AWS KMS.
    :param kms:
    :param key_id:
    :param csr:
    :param digest_algorithm:
    :param signing_algorithm:
    :return
        bytes: The signature bytes
    :raises
        botocore.exceptions.ClientError: If KMS signing operation fails
    """
    certificationRequestInfo = csr['certificationRequestInfo']
    der_bytes = encoder.encode(certificationRequestInfo)
    digest = hashlib.new(digest_algorithm)
    digest.update(der_bytes)
    digest = digest.digest()
    response = kms.sign(KeyId=key_id, Message=digest, MessageType='DIGEST', SigningAlgorithm=signing_algorithm)
    return response['Signature']


def output_csr(csr) -> None:
    """
    Output the newely created CSR.
    :param csr:
    :return: None
    """
    print(start_marker)
    b64 = base64.b64encode(encoder.encode(csr)).decode('ascii')
    for line in textwrap.wrap(b64, width=64):
        print(line)
    print(end_marker)


def signing_algorithm(hashalgo, signalgo) -> tuple[str, str]:
    """
    Get the AWS KMS signing algorithm and OID based on hash and signing algorithms.
    :param hashalgo: (str): Hash algorithm (sha224, sha256, sha384, sha512)
    :param signalgo: (str): Signing algorithm (RSA, ECDSA)
    :returns:
        tuple: (AWS KMS signing algorithm, OID)
    :raises:
        ValueError: If the algorithm combination is not supported
    """
    # Mapping of (hashalgo, signalgo) to (KMS algorithm, OID)
    ALGORITHM_MAP = {
        ('sha512', 'ECDSA'): ('ECDSA_SHA_512', '1.2.840.10045.4.3.4'),
        ('sha384', 'ECDSA'): ('ECDSA_SHA_384', '1.2.840.10045.4.3.3'),
        ('sha256', 'ECDSA'): ('ECDSA_SHA_256', '1.2.840.10045.4.3.2'),
        ('sha224', 'ECDSA'): ('ECDSA_SHA_224', '1.2.840.10045.4.3.1'),
        ('sha512', 'RSA'): ('RSASSA_PKCS1_V1_5_SHA_512', '1.2.840.113549.1.1.13'),
        ('sha384', 'RSA'): ('RSASSA_PKCS1_V1_5_SHA_384', '1.2.840.113549.1.1.12'),
        ('sha256', 'RSA'): ('RSASSA_PKCS1_V1_5_SHA_256', '1.2.840.113549.1.1.11')
    }

    key = (hashalgo, signalgo)
    if key not in ALGORITHM_MAP:
        raise ValueError(f"Unsupported algorithm combination: {hashalgo} with {signalgo}")

    return ALGORITHM_MAP[key]


def main(args):
    try:
        with open(args.csr, 'r') as f:
            try:
                substrate = pyasn1_modules.pem.readPemFromFile(f, startMarker=start_marker, endMarker=end_marker)
                csr = decoder.decode(substrate, asn1Spec=pyasn1_modules.rfc2986.CertificationRequest())[0]
                if not csr:
                    raise Exception('file does not look like a CSR')
            except Exception as e:
                raise ValueError(f"Failed to parse CSR: {e}")

        # now get the key
        try:
            if not args.region:
                args.region = boto3.session.Session().region_name

            if args.profile:
                boto3.setup_default_session(profile_name=args.profile)
            kms = boto3.client('kms', region_name=args.region)
            try:
                response = kms.get_public_key(KeyId=args.keyid)
            except boto3.exceptions.ClientError as e:
                if 'AccessDenied' in str(e):
                    raise PermissionError(f"Access denied for key {args.keyid}. Check your IAM permissions.")
                elif 'NotFoundException' in str(e):
                    raise ValueError(f"Key {args.keyid} not found in region {args.region}")
                else:
                    raise RuntimeError(f"AWS KMS error: {str(e)}")

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
        except boto3.exceptions.NoCredentialsError:
            raise RuntimeError("AWS credentials not found. Configure AWS CLI or provide a profile.")
        except boto3.exceptions.NoRegionError:
            raise ValueError("AWS region not specified and could not be determined automatically.")

    except FileNotFoundError:
        print(f"Error: CSR file '{args.csr} not found.")
        return 1
    except ValueError as e:
        print(f"Error: {str(e)}")
        return 1
    except PermissionError as e:
        print(f"Permission Error: {str(e)}")
        return 1
    except Exception as e:
        print(str(e))

    return 0

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
