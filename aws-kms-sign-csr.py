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

start_marker          = '-----BEGIN CERTIFICATE REQUEST-----'
end_marker            = '-----END CERTIFICATE REQUEST-----'
signing_algorithm     = 'RSASSA_PKCS1_V1_5_SHA_256'
signing_algorithm_oid = '1.2.840.113549.1.1.11'

def sign_certification_request_info(kms, key_id, csr):
   certificationRequestInfo = csr['certificationRequestInfo']
   der_bytes = encoder.encode(certificationRequestInfo)
   digest = hashlib.sha256(der_bytes).digest()
   response = kms.sign(KeyId=key_id, Message=digest, MessageType='DIGEST', SigningAlgorithm=signing_algorithm)
   return response['Signature']

def output_csr(csr):
   print(start_marker)
   b64 = base64.b64encode(encoder.encode(csr)).decode('ascii')
   for line in textwrap.wrap(b64, width=64):
      print(line)
   print(end_marker)


def main(args):
   with open(args.csr, 'r') as f:
      substrate = pyasn1_modules.pem.readPemFromFile(f, startMarker=start_marker, endMarker=end_marker)
      csr = decoder.decode(substrate, asn1Spec=pyasn1_modules.rfc2986.CertificationRequest())[0]
      if not csr:
         raise Exception('file does not look like a CSR')
   
   # now get the key
   if not args.region:
      args.region = boto3.session.Session().region_name

   kms = boto3.client('kms', region_name=args.region)
   
   response = kms.get_public_key(KeyId=args.keyid)
   pubkey_der = response['PublicKey']
   csr['certificationRequestInfo']['subjectPKInfo'] = decoder.decode(pubkey_der, pyasn1_modules.rfc2314.SubjectPublicKeyInfo())[0]
   
   signatureBytes = sign_certification_request_info(kms, args.keyid, csr)
   csr.setComponentByName('signature', univ.BitString.fromOctetString(signatureBytes))

   sigAlgIdentifier = pyasn1_modules.rfc2314.SignatureAlgorithmIdentifier()
   sigAlgIdentifier.setComponentByName('algorithm', univ.ObjectIdentifier(signing_algorithm_oid))
   csr.setComponentByName('signatureAlgorithm', sigAlgIdentifier)

   output_csr(csr)

if __name__ == '__main__':
   parser = argparse.ArgumentParser()
   parser.add_argument('csr', help="Source CSR (can be signed with any key)")
   parser.add_argument('--keyid', action='store', dest='keyid', help='key ID in AWS KMS')
   parser.add_argument('--region', action='store', dest='region', help='AWS region')
   args = parser.parse_args()
   main(args)

