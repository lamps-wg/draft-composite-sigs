- id-MLDSA44-RSA2048-PSS-SHA256
  - OID: 2.16.840.1.114027.80.9.1.0
  - Label: COMPSIG-MLDSA44-RSA2048-PSS-SHA256
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 2048
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA44-RSA2048-PKCS15-SHA256
  - OID: 2.16.840.1.114027.80.9.1.1
  - Label: COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha256WithRSAEncryption
    - RSA size: 2048

- id-MLDSA44-Ed25519-SHA512
  - OID: 2.16.840.1.114027.80.9.1.2
  - Label: COMPSIG-MLDSA44-Ed25519-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: Ed25519
    - Traditional Signature Algorithm: id-Ed25519

- id-MLDSA44-ECDSA-P256-SHA256
  - OID: 2.16.840.1.114027.80.9.1.3
  - Label: COMPSIG-MLDSA44-ECDSA-P256-SHA256
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: secp256r1

- id-MLDSA65-RSA3072-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.4
  - Label: COMPSIG-MLDSA65-RSA3072-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 3072
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA65-RSA3072-PKCS15-SHA512
  - OID: 2.16.840.1.114027.80.9.1.5
  - Label: COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha256WithRSAEncryption
    - RSA size: 3072

- id-MLDSA65-RSA4096-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.6
  - Label: COMPSIG-MLDSA65-RSA4096-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 4096
    - RSASSA-PSS parameters: See {{rsa-pss-params4096}}

- id-MLDSA65-RSA4096-PKCS15-SHA512
  - OID: 2.16.840.1.114027.80.9.1.7
  - Label: COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha384WithRSAEncryption
    - RSA size: 4096

- id-MLDSA65-ECDSA-P256-SHA512
  - OID: 2.16.840.1.114027.80.9.1.8
  - Label: COMPSIG-MLDSA65-P256-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: secp256r1

- id-MLDSA65-ECDSA-P384-SHA512
  - OID: 2.16.840.1.114027.80.9.1.9
  - Label: COMPSIG-MLDSA65-P384-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: secp384r1

- id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - OID: 2.16.840.1.114027.80.9.1.10
  - Label: COMPSIG-MLDSA65-BP256-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: brainpoolP256r1

- id-MLDSA65-Ed25519-SHA512
  - OID: 2.16.840.1.114027.80.9.1.11
  - Label: COMPSIG-MLDSA65-Ed25519-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: Ed25519
    - Traditional Signature Algorithm: id-Ed25519

- id-MLDSA87-ECDSA-P384-SHA512
  - OID: 2.16.840.1.114027.80.9.1.12
  - Label: COMPSIG-MLDSA87-P384-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: secp384r1

- id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - OID: 2.16.840.1.114027.80.9.1.13
  - Label: COMPSIG-MLDSA87-BP384-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: brainpoolP384r1

- id-MLDSA87-Ed448-SHAKE256
  - OID: 2.16.840.1.114027.80.9.1.14
  - Label: COMPSIG-MLDSA87-Ed448-SHAKE256
  - Pre-Hash function (PH): SHAKE256/64**
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: Ed448
    - Traditional Signature Algorithm: id-Ed448

- id-MLDSA87-RSA3072-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.15
  - Label: COMPSIG-MLDSA87-RSA3072-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 3072
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA87-RSA4096-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.16
  - Label: COMPSIG-MLDSA87-RSA4096-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 4096
    - RSASSA-PSS parameters: See {{rsa-pss-params4096}}

- id-MLDSA87-ECDSA-P521-SHA512
  - OID: 2.16.840.1.114027.80.9.1.17
  - Label: COMPSIG-MLDSA87-P521-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA512
    - ECDSA curve: secp521r1

