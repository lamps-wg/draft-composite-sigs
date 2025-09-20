- id-MLDSA44-RSA2048-PSS-SHA256
  - OID: 2.16.840.1.114027.80.9.1.20
  - Label: COMPSIG-MLDSA44-RSA2048-PSS-SHA256
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 2048
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA44-RSA2048-PKCS15-SHA256
  - OID: 2.16.840.1.114027.80.9.1.21
  - Label: COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha256WithRSAEncryption
    - RSA size: 2048

- id-MLDSA44-Ed25519-SHA512
  - OID: 2.16.840.1.114027.80.9.1.22
  - Label: COMPSIG-MLDSA44-Ed25519-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: Ed25519
    - Traditional Signature Algorithm: id-Ed25519

- id-MLDSA44-ECDSA-P256-SHA256
  - OID: 2.16.840.1.114027.80.9.1.23
  - Label: COMPSIG-MLDSA44-ECDSA-P256-SHA256
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: secp256r1

- id-MLDSA65-RSA3072-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.24
  - Label: COMPSIG-MLDSA65-RSA3072-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 3072
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA65-RSA3072-PKCS15-SHA512
  - OID: 2.16.840.1.114027.80.9.1.25
  - Label: COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha256WithRSAEncryption
    - RSA size: 3072

- id-MLDSA65-RSA4096-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.26
  - Label: COMPSIG-MLDSA65-RSA4096-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 4096
    - RSASSA-PSS parameters: See {{rsa-pss-params4096}}

- id-MLDSA65-RSA4096-PKCS15-SHA512
  - OID: 2.16.840.1.114027.80.9.1.27
  - Label: COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha384WithRSAEncryption
    - RSA size: 4096

- id-MLDSA65-ECDSA-P256-SHA512
  - OID: 2.16.840.1.114027.80.9.1.28
  - Label: COMPSIG-MLDSA65-P256-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: secp256r1

- id-MLDSA65-ECDSA-P384-SHA512
  - OID: 2.16.840.1.114027.80.9.1.29
  - Label: COMPSIG-MLDSA65-P384-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: secp384r1

- id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - OID: 2.16.840.1.114027.80.9.1.30
  - Label: COMPSIG-MLDSA65-BP256-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: brainpoolP256r1

- id-MLDSA65-Ed25519-SHA512
  - OID: 2.16.840.1.114027.80.9.1.31
  - Label: COMPSIG-MLDSA65-Ed25519-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: Ed25519
    - Traditional Signature Algorithm: id-Ed25519

- id-MLDSA87-ECDSA-P384-SHA512
  - OID: 2.16.840.1.114027.80.9.1.32
  - Label: COMPSIG-MLDSA87-P384-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: secp384r1

- id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - OID: 2.16.840.1.114027.80.9.1.33
  - Label: COMPSIG-MLDSA87-BP384-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: brainpoolP384r1

- id-MLDSA87-Ed448-SHAKE256
  - OID: 2.16.840.1.114027.80.9.1.34
  - Label: COMPSIG-MLDSA87-Ed448-SHAKE256
  - Pre-Hash function (PH): SHAKE256/64**
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: Ed448
    - Traditional Signature Algorithm: id-Ed448

- id-MLDSA87-RSA3072-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.35
  - Label: COMPSIG-MLDSA87-RSA3072-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 3072
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA87-RSA4096-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.36
  - Label: COMPSIG-MLDSA87-RSA4096-PSS-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 4096
    - RSASSA-PSS parameters: See {{rsa-pss-params4096}}

- id-MLDSA87-ECDSA-P521-SHA512
  - OID: 2.16.840.1.114027.80.9.1.37
  - Label: COMPSIG-MLDSA87-P521-SHA512
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA512
    - ECDSA curve: secp521r1

