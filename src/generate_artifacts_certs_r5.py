#!/usr/bin/env python3

import json
from zipfile import ZipFile
import base64

from pyasn1.type import univ

OID_TABLE = {
    "ecdsa-with-SHA256": univ.ObjectIdentifier((1,2,840,10045,4,3,2)),
    "ecdsa-with-SHA384": univ.ObjectIdentifier((1,2,840,10045,4,3,3)),
    "id-Ed25519": univ.ObjectIdentifier((1,3,101,112)),
    "id-Ed448": univ.ObjectIdentifier((1,3,101,113)),
    "id-ML-DSA-44": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,17)),
    "id-ML-DSA-65": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18)),
    "id-ML-DSA-87": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,19)),
    "id-MLDSA44-RSA2048-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,60)),
    "id-MLDSA44-RSA2048-PKCS15": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,61)),
    "id-MLDSA44-Ed25519": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,62)),
    "id-MLDSA44-ECDSA-P256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,63)),
    "id-MLDSA65-RSA3072-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,64)),
    "id-MLDSA65-RSA3072-PKCS15": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,65)),
    "id-MLDSA65-RSA4096-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,66)),
    "id-MLDSA65-RSA4096-PKCS15": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,67)),
    "id-MLDSA65-ECDSA-P256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,68)),
    "id-MLDSA65-ECDSA-P384": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,69)),
    "id-MLDSA65-ECDSA-brainpoolP256r1": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,70)),
    "id-MLDSA65-Ed25519": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,71)),
    "id-MLDSA87-ECDSA-P384": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,72)),
    "id-MLDSA87-ECDSA-brainpoolP384r1": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,73)),
    "id-MLDSA87-Ed448": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,74)),
    "id-MLDSA87-RSA4096-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,75)),
    "id-HashMLDSA44-RSA2048-PSS-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,80)),
    "id-HashMLDSA44-RSA2048-PKCS15-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,81)),
    "id-HashMLDSA44-Ed25519-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,82)),
    "id-HashMLDSA44-ECDSA-P256-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,83)),
    "id-HashMLDSA65-RSA3072-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,84)),
    "id-HashMLDSA65-RSA3072-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,85)),
    "id-HashMLDSA65-RSA4096-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,86)),
    "id-HashMLDSA65-RSA4096-PKCS15-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,87)),
    "id-HashMLDSA65-ECDSA-P256-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,88)),
    "id-HashMLDSA65-ECDSA-P384-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,89)),
    "id-HashMLDSA65-ECDSA-brainpoolP256r1-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,90)),
    "id-HashMLDSA65-Ed25519-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,91)),
    "id-HashMLDSA87-ECDSA-P384-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,92)),
    "id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,93)),
    "id-HashMLDSA87-RSA4096-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,95))
}


with open('testvectors.json') as f:
    test_vectors = json.load(f)

artifacts_zip = ZipFile('artifacts_certs_r5.zip', mode='w')

for tc in test_vectors['tests']:
    try:
        # <friendlyname>-<oid>_ta.der
        certFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_ta.der"
        keyFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_priv.raw"
    except KeyError:
        # if this one is not in the OID_TABLE, then just skip it
        continue
    
    artifacts_zip.writestr(certFilename, data=base64.b64decode(tc['x5c']))
    artifacts_zip.writestr(keyFilename, data=base64.b64decode(tc['sk']))





