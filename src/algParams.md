- id-MLDSA44-RSA2048-PSS-SHA256
  - OID: 2.16.840.1.114027.80.9.1.0
  - Domain Separator: 060B6086480186FA6B50090100
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 2048
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA44-RSA2048-PKCS15-SHA256
  - OID: 2.16.840.1.114027.80.9.1.1
  - Domain Separator: 060B6086480186FA6B50090101
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha256WithRSAEncryption
    - RSA size: 2048

- id-MLDSA44-Ed25519-SHA512
  - OID: 2.16.840.1.114027.80.9.1.2
  - Domain Separator: 060B6086480186FA6B50090102
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: Ed25519
    - Traditional Signature Algorithm: id-Ed25519

- id-MLDSA44-ECDSA-P256-SHA256
  - OID: 2.16.840.1.114027.80.9.1.3
  - Domain Separator: 060B6086480186FA6B50090103
  - Pre-Hash function (PH): SHA256
  - ML-DSA variant: ML-DSA-44
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: secp256r1

- id-MLDSA65-RSA3072-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.4
  - Domain Separator: 060B6086480186FA6B50090104
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 3072
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA65-RSA3072-PKCS15-SHA512
  - OID: 2.16.840.1.114027.80.9.1.5
  - Domain Separator: 060B6086480186FA6B50090105
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha256WithRSAEncryption
    - RSA size: 3072

- id-MLDSA65-RSA4096-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.6
  - Domain Separator: 060B6086480186FA6B50090106
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 4096
    - RSASSA-PSS parameters: See {{rsa-pss-params4096}}

- id-MLDSA65-RSA4096-PKCS15-SHA512
  - OID: 2.16.840.1.114027.80.9.1.7
  - Domain Separator: 060B6086480186FA6B50090107
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: sha384WithRSAEncryption
    - RSA size: 4096

- id-MLDSA65-ECDSA-P256-SHA512
  - OID: 2.16.840.1.114027.80.9.1.8
  - Domain Separator: 060B6086480186FA6B50090108
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: secp256r1

- id-MLDSA65-ECDSA-P384-SHA512
  - OID: 2.16.840.1.114027.80.9.1.9
  - Domain Separator: 060B6086480186FA6B50090109
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: secp384r1

- id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - OID: 2.16.840.1.114027.80.9.1.10
  - Domain Separator: 060B6086480186FA6B5009010A
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA256
    - ECDSA curve: brainpoolP256r1

- id-MLDSA65-Ed25519-SHA512
  - OID: 2.16.840.1.114027.80.9.1.11
  - Domain Separator: 060B6086480186FA6B5009010B
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-65
  - Traditional Algorithm: Ed25519
    - Traditional Signature Algorithm: id-Ed25519

- id-MLDSA87-ECDSA-P384-SHA512
  - OID: 2.16.840.1.114027.80.9.1.12
  - Domain Separator: 060B6086480186FA6B5009010C
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: secp384r1

- id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - OID: 2.16.840.1.114027.80.9.1.13
  - Domain Separator: 060B6086480186FA6B5009010D
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA384
    - ECDSA curve: brainpoolP384r1

- id-MLDSA87-Ed448-SHAKE256
  - OID: 2.16.840.1.114027.80.9.1.14
  - Domain Separator: 060B6086480186FA6B5009010E
  - Pre-Hash function (PH): SHAKE256/64**
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: Ed448
    - Traditional Signature Algorithm: id-Ed448

- id-MLDSA87-RSA3072-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.15
  - Domain Separator: 060B6086480186FA6B5009010F
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 3072
    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}

- id-MLDSA87-RSA4096-PSS-SHA512
  - OID: 2.16.840.1.114027.80.9.1.16
  - Domain Separator: 060B6086480186FA6B50090110
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: RSA
    - Traditional Signature Algorithm: id-RSASSA-PSS
    - RSA size: 4096
    - RSASSA-PSS parameters: See {{rsa-pss-params4096}}

- id-MLDSA87-ECDSA-P521-SHA512
  - OID: 2.16.840.1.114027.80.9.1.17
  - Domain Separator: 060B6086480186FA6B50090111
  - Pre-Hash function (PH): SHA512
  - ML-DSA variant: ML-DSA-87
  - Traditional Algorithm: ECDSA
    - Traditional Signature Algorithm: ecdsa-with-SHA512
    - ECDSA curve: secp521r1

