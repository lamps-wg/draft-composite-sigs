---
title: Composite ML-DSA For use in X.509 Public Key Infrastructure and CMS
abbrev: Composite ML-DSA
docname: draft-ietf-lamps-pq-composite-sigs-latest

ipr: trust200902
area: Security
wg: LAMPS
kw: Internet-Draft
cat: std

venue:
  group: LAMPS
  type: Working Group
  mail: spams@ietf.org
  arch: https://datatracker.ietf.org/wg/lamps/about/
  github: lamps-wg/draft-composite-sigs
  latest: https://lamps-wg.github.io/draft-composite-sigs/draft-ietf-lamps-pq-composite-sigs.html

coding: utf-8
pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:   # defaults to yes
  symrefs: yes

author:
  -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com
  -
    ins: J. Gray
    name: John Gray
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: john.gray@entrust.com
  -
    ins: M. Pala
    name: Massimiliano Pala
    org: OpenCA Labs
    city: New York City, New York
    country: United States of America
    email: director@openca.org
  -
    ins: J. Klaussner
    name: Jan Klaussner
    org: Bundesdruckerei GmbH
    email: jan.klaussner@bdr.de
    street: Kommandantenstr. 18
    code: 10969
    city: Berlin
    country: Germany
  -
    ins: S. Fluhrer
    name: Scott Fluhrer
    org: Cisco Systems
    email: sfluhrer@cisco.com


normative:
  RFC2119:
  RFC2986:
  RFC4210:
  RFC4211:
  RFC5280:
  RFC5480:
  RFC5639:
  RFC5652:
  RFC5758:
  RFC5958:
  RFC6090:
  RFC6234:
  RFC7748:
  RFC8032:
  RFC8174:
  RFC8410:
  RFC8411:
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015
  FIPS.186-5:
    title: "Digital Signature Standard (DSS)"
    date: February 3, 2023
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
  FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 13, 2024
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf


informative:
  RFC3279:
  RFC5914:
  RFC7292:
  RFC7296:
  RFC7299:
  RFC8446:
  RFC8551:
  RFC8017:
  I-D.draft-ietf-pquip-hybrid-signature-spectrums-00:
  #I-D.draft-ounsworth-pq-composite-kem-01:
  I-D.draft-pala-klaussner-composite-kofn-00:
  I-D.draft-ietf-pquip-pqt-hybrid-terminology-04:
  I-D.draft-ietf-lamps-dilithium-certificates-04:
  I-D.draft-salter-lamps-cms-ml-dsa-00:
  Bindel2017:
    title: "Transitioning to a quantum-resistant public key infrastructure"
    target: "https://link.springer.com/chapter/10.1007/978-3-319-59879-6_22"
    author:
      -
        ins: N. Bindel
        name: Nina Bindel
      -
        ins: U. Herath
        name: Udyani Herath
      -
        ins: M. McKague
        name: Matthew McKague
      -
        ins: D. Stebila
        name: Douglas Stebila
    date: 2017
  BSI2021:
    title: "Quantum-safe cryptography - fundamentals, current developments and recommendations"
    target: https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/Brochure/quantum-safe-cryptography.pdf
    author:
      - org: "Federal Office for Information Security (BSI)"
    date: October 2021
  ANSSI2024:
    title: "Position Paper on Quantum Key Distribution"
    target: https://cyber.gouv.fr/sites/default/files/document/Quantum_Key_Distribution_Position_Paper.pdf
    author:
      - org: "French Cybersecurity Agency (ANSSI)"
      - org: "Federal Office for Information Security (BSI)"
      - org: "Netherlands National Communications Security Agency (NLNCSA)"
      - org: "Swedish National Communications Security Authority, Swedish Armed Forces"


--- abstract

This document defines combinations of ML-DSA [FIPS.204] in hybrid with traditional algorithms RSA-PKCS#1v1.5, RSA-PSS, ECDSA, Ed25519, and Ed448. These combinations are tailored to meet security best practices and regulatory requirements. Composite ML-DSA is applicable in any application that uses X.509, PKIX, and CMS data structures and protocols that accept ML-DSA, but where the operator wants extra protection against breaks or catastrophic bugs in ML-DSA.

<!-- End of Abstract -->


--- middle


# Changes in -03

Interop-affecting changes:

* Compacted CompositeSignaturePrivateKey to SEQUENCE SIZE (2) OF OCTET STRING instead of OneAsymmetricKey to remove redundancy
* Added support for the ML-DSA context String, and use the Composite Domain as the context for the underlying ML-DSA component algorithm.
* Added Pre-Hash and Pure modes and changed the Message format to align with FIPS-204.  This breaks backwards compatibility with all previous versions.
* Updated the OID table for new Pre-Hash OIDs and added them to the IANA section.
* Updated Use in CMS section to reflect content is hashed and pure Composite ML-DSA should be used.

Editorial changes:

* Added the ASN.1 encodings for the component public keys and signature algorithm identifiers
* ASN.1 Module changes:
  * Renamed the module from Composite-Signatures-2023 -> Composite-MLDSA-2024
  * Simplified the ASN.1 module to make it more compiler-friendly (thanks Carl!) -- should not affect wire encodings.
* Updated Security Considerations about Non-separability, EUF-CMA and key reuse.


# Introduction {#sec-intro}

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic algorithms such as RSA, Diffie-Hellman, DSA, and their elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify potential implementation flaws.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward. Even after the migration period, it may be advantageous for an entity's cryptographic identity to incorporate multiple public-key algorithms to enhance security.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of Composite scheme provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies [BSI2021].

Composite ML-DSA is applicable in any application that would otherwise use ML-DSA, but wants the protection against breaks or catastrophic bugs in ML-DSA.

## Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14+}

This document is consistent with the terminology defined in {{I-D.ietf-pquip-pqt-hybrid-terminology}}. In addition, the following terminology is used throughout this document:

**ALGORITHM**:
          The usage of the term "algorithm" within this
          document generally refers to any function which
          has a registered Object Identifier (OID) for
          use within an ASN.1 AlgorithmIdentifier. This
          loosely, but not precisely, aligns with the
          definitions of "cryptographic algorithm" and
          "cryptographic scheme" given in {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

**BER**:
          Basic Encoding Rules (BER) as defined in [X.690].

**CLIENT**:
          Any software that is making use of a cryptographic key.
          This includes a signer, verifier, encrypter, decrypter.
          This is not meant to imply any sort of client-server
          relationship between the communicating parties.

**DER**:
          Distinguished Encoding Rules as defined in [X.690].

**PKI**:
          Public Key Infrastructure, as defined in [RFC5280].

**PUBLIC / PRIVATE KEY**:
          The public and private portion of an asymmetric cryptographic
          key, making no assumptions about which algorithm.

**SIGNATURE**:
          A digital cryptographic signature, making no assumptions
            about which algorithm.

## Composite Design Philosophy

{{I-D.ietf-pquip-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite keys, as defined here, follow this definition and should be regarded as a single key that performs a single cryptographic operation such as key generation, signing, verifying, encapsulating, or decapsulating -- using its internal sequence of component keys as if they form a single key. This generally means that the complexity of combining algorithms can and should be handled by the cryptographic library or cryptographic module, and the single composite public key, private key, ciphertext and signature can be carried in existing fields in protocols such as PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652], and the Trust Anchor Format [RFC5914]. In this way, composites achieve "protocol backwards-compatibility" in that they will drop cleanly into any protocol that accepts an analogous single-algorithm cryptographic scheme without requiring any modification of the protocol to handle multiple algorithms.


# Overview of the Composite ML-DSA Signature Scheme

Composite schemes are defined as cryptographic primitives that consist of three algorithms:

   *  `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
      which generates a public key pk and a secret key sk.

   *  `Sign(sk, Message) -> (signature)`: A signing algorithm which takes
      as input a secret key sk and a Message, and outputs a signature

   *  `Verify(pk, Message, signature) -> true or false`: A verification algorithm
      which takes as input a public key, a Message, and a signature and outputs true
      if the signature verifies correctly.  Thus it proves the Message was signed
      with the secret key associated with the public key and verifies the integrity
      of the Message.  If the signature and public key cannot verify the Message,
      it returns false.

A composite signature allows the security properties of the two underlying algorithms to be combined via standard signature operations `Sign()` and `Verify()`.

This specification uses the Post-Quantum signature scheme ML-DSA as specified in [FIPS.204] and {{I-D.ietf-lamps-dilithium-certificates}}. For Traditional signature schemes, this document uses the RSA PKCS#1v1.5 and RSA-PSS algorithms defined in [RFC8017], the Elliptic Curve Digital Signature Algorithm ECDSA scheme defined in section 6 of [FIPS.186-5], and Ed25519 / Ed448 which are defined in [RFC8410]. A simple "signature combiner"function which prepends a domain separator value specific to the composite algorithm is used to bind the two component signatures to the composite algorithm and achieve weak non-separablity.

## Pure vs Pre-hashed modes

In [FIPS.204] NIST defined ML-DSA to have both pure and pre-hashed signing modes, referred to as "ML-DSA" and "HashML-DSA" respectively. Following this, this document defines "Composite-ML-DSA" and "HashComposite-ML-DSA" which mirror the external functions defined in [FIPS.204].

# Composite ML-DSA Functions {#sec-sigs}

## Key Generation

To generate a new keypair for Composite schemes, the `KeyGen() -> (pk, sk)` function is used. The KeyGen() function calls the two key generation functions of the component algorithms for the Composite keypair in no particular order. Multi-process or multi-threaded applications might choose to execute the key generation functions in parallel for better key generation performance.

The following process is used to generate composite keypair values:

~~~
KeyGen() -> (pk, sk)

Explicit inputs:

  None

Implicit inputs:

  ML-DSA     A placeholder for the specific ML-DSA algorithm and
             parameter set to use, for example, could be "ML-DSA-65".

  Trad       A placeholder for the specific traditional algorithm and
             parameter set to use, for example "RSASA-PSS"
             or "Ed25519".

Output:

  (pk, sk)   The composite keypair.

Key Generation Process:

  1. Generate component keys

      (mldsaPK, mldsaSK) = ML-DSA.KeyGen()
      (tradPK, tradSK)   = Trad.KeyGen()

  2. Check for component key gen failure

      if NOT (mldsaPK, mldsaSK) or NOT (tradPK, tradSK):
        output "Key generation error"

  3. Encode the component keys into composite structures

      pk = CompositeSignaturePublicKey(mldsaPK, tradPK)
      sk = CompositeSignaturePrivateKey(mldsaSK, tradSK)

  4. Output the composite keys

      return (pk, sk)

~~~
{: #alg-composite-keygen title="Composite KeyGen(pk, sk)"}

The structures CompositeSignaturePublicKey and CompositeSignaturePrivateKey are described in {{sec-composite-pub-keys}} and {{sec-priv-key}} respectively and are used here as placeholders since implementations MAY use their own internal key representations in cases where interoperability is not required.

In order to ensure fresh keys, the key generation functions MUST be executed for both component algorithms. Compliant parties MUST NOT use or import component keys that are used in other contexts, combinations, or by themselves as keys for standalone algorithm use. For more details on the security considerations around key reuse, see section {{sec-cons-key-reuse}}.

Note that in step 2 above, both component key generation processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

## Pure Signature Mode {#sec-comp-sig-gen}

This mode mirrors `HashML-DSA` defined in Sections 5.2 and 5.3 of [FIPS.204].

In the pure mode the Domain separator value is concatenated with the length of the context in bytes, the context, and the message to be signed.  After that, the signature process for each component algorithm is invoked and the values are then placed in the CompositeSignatureValue structure defined in {{sec-composite-sig-structs}}.

A composite signature's value MUST include two signature components and MUST be in the same order as the components from the corresponding signing key.


### Composite-ML-DSA.Sign

This mode mirrors `ML-DSA.Sign(sk, M, ctx)` defined in Algorithm 2 in Section 5.2 of [FIPS.204].

~~~
Composite-ML-DSA.Sign (sk, M, ctx) -> (signature)

Explicit inputs:

  sk    Composite private key consisting of signing private keys for
        each component.

  M     The Message to be signed, an octet string.

  ctx   The Message context string, which defaults to the empty string.


Implicit inputs:

  ML-DSA   A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example, could be "ML-DSA-65".

  Trad     A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example "RSASA-PSS with id-sha256"
           or "Ed25519".

  Domain   Domain separator value for binding the signature to the
           Composite OID. See section on Domain Separators below.

Output:

  signature   The composite signature, a CompositeSignatureValue.

Signature Generation Process:

  1. If |ctx| > 255:
      return error

  2. Compute the Message M'.

      M' = Domain || len(ctx) || ctx || M

  3. Separate the private key into component keys.

      (mldsaSK, tradSK) = sk

  4. Generate the 2 component signatures independently, by calculating
     the signature over M' according to their algorithm specifications.

      mldsaSig = ML-DSA.Sign( mldsaSK, M', ctx=Domain )
      tradSig = Trad.Sign( tradSK, M' )

  5. If either ML-DSA.Sign() or Trad.Sign() return an error, then this
     process must return an error.

      if NOT mldsaSig or NOT tradSig:
        output "Signature generation error"

   6. Encode each component signature into a CompositeSignatureValue.

      signature := CompositeSignatureValue(mldsaSig, tradSig)

  7. Output signature

      return signature
~~~
{: # title="Composite-ML-DSA.Sign(sk, M, ctx)"}

It is possible to use component private keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this document so long as it produces the same output and error handling as the process sketched above.

Note that in step 5 above, both component signature processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

### Composite-ML-DSA.Verify {#sec-comp-sig-verify}

This mode mirrors `ML-DSA.Verify(pk, M, signature, ctx)` defined in Algorithm 3 in Section 5.3 of [FIPS.204].

Compliant applications MUST output "Valid signature" (true) if and only if all component signatures were successfully validated, and "Invalid signature" (false) otherwise.

~~~
Composite-ML-DSA.Verify(pk, M, signature, ctx)

Explicit inputs:

  pk          Composite public key conisting of verification public keys
              for each component.

  M           Message whose signature is to be verified,
              an octet string.

  signature   CompositeSignatureValue containing the component
              signature values (mldsaSig and tradSig) to be verified.

  ctx         The Message context string, which defaults to the empty
              string.

Implicit inputs:

  ML-DSA   A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example, could be "ML-DSA-65".

  Trad     A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example "RSASA-PSS with id-sha256"
           or "Ed25519".

  Domain   Domain separator value for binding the signature to the
           Composite OID. See section on Domain Separators below.


Output:
    Validity (bool)    "Valid signature" (true) if the composite
                        signature is valid, "Invalid signature"
                        (false) otherwise.

Signature Verification Process:

  1. If |ctx| > 255
      return error

  2. Separate the keys and signatures

        (pk1, pk2) = pk
        (s1, s2)   = signature

    If Error during Desequencing, or if any of the component
    keys or signature values are not of the correct key type or
    length for the given component algorithm then output
    "Invalid signature" and stop.

  3. Compute the Message M'.

        M' = Domain || len(ctx) || ctx || M

  4. Check each component signature individually, according to its
     algorithm specification.
     If any fail, then the entire signature validation fails.

        if not ML-DSA.Verify( pk1, M', s1, ctx=Domain) then
          output "Invalid signature"

        if not Trad.Verify( pk2, M', s2) then
          output "Invalid signature"

        if all succeeded, then
          output "Valid signature"
~~~
{: #alg-composite-verify title="Composite-ML-DSA.Verify(pk, Message, signature, Context)"}

Note that in step 4 above, the function fails early if the first component fails to verify. Since no private keys are involved in a signature verification, there are no timing attacks to consider, so this is ok.

## PreHash-Signature Mode {#sec-comp-sig-gen-prehash}

This mode mirrors `HashML-DSA` defined in Section 5.4 of [FIPS.204].

In the pre-hash mode the Domain separator {{sec-domsep-values}} is concatenated with the length of the context in bytes, the context, an additional DER encoded value that represents the OID of the Hash function and finally the hash of the message to be signed.  After that, the signature process for each component algorithm is invoked and the values are then placed in the CompositeSignatureValue structure defined in {{sec-composite-sig-structs}}.

A composite signature's value MUST include two signature components and MUST be in the same order as the components from the corresponding signing key.


### HashComposite-ML-DSA-Sign signature mode {#sec-hash-comp-sig-sign}

This mode mirrors `HashML-DSA.Sign(sk, M, ctx, PH)` defined in Section 5.4.1 of [FIPS.204].

In the pre-hash mode the Domain separator {{sec-domsep-values}} is concatenated with the length of the context in bytes, the context, an additional DER encoded value that indicates which Hash function was used for the pre-hash and finally the pre-hashed message `PH(M)`.

~~~
HashComposite-ML-DSA.Sign (sk, M, ctx, PH) -> (signature)

Explicit inputs:

  sk    Composite private key consisting of signing private keys for
        each component.

  M     The Message to be signed, an octet string.

  ctx   The Message context string, which defaults to the empty string

  PH    The Message Digest Algorithm for pre-hashing.  See
        section on pre-hashing the message below.

Implicit inputs:

  ML-DSA   A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example, could be "ML-DSA-65".

  Trad     A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example "RSASA-PSS with id-sha256"
           or "Ed25519".

 Domain    Domain separator value for binding the signature to the
           Composite OID. See section on Domain Separators below.

 HashOID   The DER Encoding of the Object Identifier of the
           PreHash algorithm (PH) which is passed into the function.

Output:
  signature   The composite signature, a CompositeSignatureValue.

Signature Generation Process:

  1. If |ctx| > 255:
      return error

  2. Compute the Message format M'.

        M' :=  Domain || len(ctx) || ctx || HashOID || PH(M)

  3. Separate the private key into component keys.

       (mldsaSK, tradSK) = sk

  4. Generate the 2 component signatures independently, by calculating
     the signature over M' according to their algorithm specifications.

       mldsaSig = ML-DSA.Sign( mldsaSK, M', ctx=Domain )
       tradSig = Trad.Sign( tradSK, M' )

  5. If either ML-DSA.Sign() or Trad.Sign() return an error, then this
     process must return an error.

      if NOT mldsaSig or NOT tradSig:
        output "Signature generation error"

  6. Encode each component signature into a CompositeSignatureValue.

      signature := CompositeSignatureValue(mldsaSig, tradSig)

  7. Output signature

      return signature
~~~
{: #alg-hash-composite-sign title="HashComposite-ML-DSA.Sign(sk, M, ctx, PH)"}

It is possible to use component private keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this document so long as it produces the same output and error handling as the process sketched above.

Note that in step 5 above, both component signature processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

### HashComposite-ML-DSA-Verify {#sec-hash-comp-sig-verify}

This mode mirrors `HashML-DSA.Verify(pk, M, signature, ctx, PH)` defined in Section 5.4.1 of [FIPS.204].

Compliant applications MUST output "Valid signature" (true) if and only if all component signatures were successfully validated, and "Invalid signature" (false) otherwise.

~~~
HashComposite-ML-DSA.Verify(pk, M, signature, ctx, PH)

Explicit inputs:

  pk          Composite public key consisting of verification public
              keys for each component.

  M           Message whose signature is to be verified, an octet
              string.

  signature   CompositeSignatureValue containing the component
              signature values (mldsaSig and tradSig) to be verified.

  ctx         The Message context string, which defaults to the empty
              string.

  PH          The Message Digest Algorithm for pre-hashing. See
              section on pre-hashing the message below.

Implicit inputs:

  ML-DSA    A placeholder for the specific ML-DSA algorithm and
            parameter set to use, for example, could be "ML-DSA-65".

  Trad      A placeholder for the specific ML-DSA algorithm and
            parameter set to use, for example "RSASA-PSS with id-sha256"
            or "Ed25519".

  Domain    Domain separator value for binding the signature to the
            Composite OID. See section on Domain Separators below.

  HashOID   The DER Encoding of the Object Identifier of the
            PreHash algorithm (PH) which is passed into the function.

Output:

  Validity (bool)   "Valid signature" (true) if the composite
                    signature is valid, "Invalid signature"
                    (false) otherwise.

Signature Verification Process:

  1. If |ctx| > 255
       return error

  2. Separate the keys and signatures

     (pk1, pk2) = pk
      (s1, s2) = signature

   If Error during Desequencing, or if any of the component
   keys or signature values are not of the correct key type or
   length for the given component algorithm then output
   "Invalid signature" and stop.

  3. Compute a Hash of the Message.

      M' = Domain || len(ctx) || ctx || HashOID || PH(M)

  4. Check each component signature individually, according to its
     algorithm specification.
     If any fail, then the entire signature validation fails.

      if not ML-DSA.Verify( pk1, M', s1, ctx=Domain ) then
          output "Invalid signature"

      if not Trad.Verify( pk2, M', s2 ) then
          output "Invalid signature"

      if all succeeded, then
         output "Valid signature"
~~~
{: #alg-hash-composite-verify title="HashComposite-ML-DSA.Verify(pk, M, signature, ctx, PH)"}

Note that in step 4 above, the function fails early if the first component fails to verify. Since no private keys are involved in a signature verification, there are no timing attacks to consider, so this is ok.


# Composite Key Structures {#sec-composite-structs}

In order to form composite public keys and signature values, we define ASN.1-based composite encodings such that these structures can be used as a drop-in replacement for existing public key and signature fields such as those found in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652].


## CompositeSignaturePublicKey {#sec-composite-pub-keys}

The wire encoding of a Composite ML-DSA public key is:

~~~ ASN.1
CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
~~~
{: artwork-name="CompositeSignaturePublicKey-asn.1-structures"}

Since RSA and ECDSA component public keys are themselves in a DER encoding, the following ASN.1 structures show the internal structure of the various public key types used in this specification:

~~~ ASN.1
RsaCompositeSignaturePublicKey ::= SEQUENCE {
        firstPublicKey BIT STRING (ENCODED BY id-raw-key),
        secondPublicKey BIT STRING (CONTAINING RSAPublicKey)
      }	

EcCompositeSignaturePublicKey ::= SEQUENCE {
        firstPublicKey BIT STRING (ENCODED BY id-raw-key),
        secondPublicKey BIT STRING (CONTAINING ECPoint)
      }	

EdCompositeSignaturePublicKey ::= SEQUENCE {
        firstPublicKey BIT STRING (ENCODED BY id-raw-key),
        secondPublicKey BIT STRING (ENCODED BY id-raw-key)
      }
~~~

`id-raw-key` is defined by this document. It signifies that the public key has no ASN.1 wrapping and the raw bits are placed here according to the encoding of the underlying algorithm specification. In some situations and protocols, the key might be wrapped in ASN.1 or
may have some other additional decoration or encoding. If so, such wrapping MUST be removed prior to encoding the key itself as a BIT STRING.

For use with this document, ML-DSA keys MUST be be the raw BIT STRING representation as specified in {{I-D.ietf-lamps-dilithium-certificates}} and Edwards Curve keys MUST be the raw BIT STRING representation as specified in [RFC8410].

Some applications may need to reconstruct the `SubjectPublicKeyInfo` objects corresponding to each component public key. {{tab-sig-algs}} or {{tab-hash-sig-algs}} in {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction. This also motivates the design choice of `SEQUENCE OF BIT STRING` instead of `SEQUENCE OF OCTET STRING`; using `BIT STRING` allows for easier transcription between CompositeSignaturePublicKey and SubjectPublicKeyInfo.

When the CompositeSignaturePublicKey must be provided in octet string or bit string format, the data structure is encoded as specified in {{sec-encoding-rules}}.

Component keys of a CompositeSignaturePublicKey MUST NOT be used in any other type of key or as a standalone key. For more details on the security considerations around key reuse, see section {{sec-cons-key-reuse}}.

The following ASN.1 Information Object Class is defined to allow for compact definitions of each composite algorithm, leading to a smaller overall ASN.1 module.

~~~ ASN.1
pk-CompositeSignature {OBJECT IDENTIFIER:id, PublicKeyType}
    PUBLIC-KEY ::= {
      IDENTIFIER id
      KEY PublicKeyType
      PARAMS ARE absent
      CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyCertSign, cRLSign}
    }
~~~

As an example, the public key type `id-MLDSA44-ECDSA-P256` is defined as:

~~~
id-MLDSA44-ECDSA-P256 PUBLIC-KEY ::=
  pk-CompositeSignature{
    id-MLDSA44-ECDSA-P256,
    EcCompositeSignaturePublicKey }
~~~

The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.


## CompositeSignaturePrivateKey {#sec-priv-key}

When a Composite ML-DSA private key is to be exported from a cryptographic module, it uses an analogous definition to the public keys:

~~~ ASN.1
CompositeSignaturePrivateKey ::= SEQUENCE SIZE (2) OF OCTET STRING
~~~
{: artwork-name="CompositeSignaturePrivateKey-asn.1-structures"}

Each element of the `CompositeSignaturePrivateKey` Sequence is an `OCTET STRING` according to the encoding of the underlying algorithm specification and will decode into the respective private key structures in an analogous way to the public key structures defined in {{sec-composite-pub-keys}}. This document does not provide helper classes for private keys.  The PrivateKey for each component algorithm MUST be in the same order as defined in {{sec-composite-pub-keys}}.


Use cases that require an interoperable encoding for composite private keys will often need to place a `CompositeSignaturePrivateKey` inside a `OneAsymmetricKey` structure defined in [RFC5958], such as when private keys are carried in PKCS #12 [RFC7292], CMP [RFC4210] or CRMF [RFC4211]. The definition of `OneAsymmetricKey` is copied here for convenience:

~~~ ASN.1
 OneAsymmetricKey ::= SEQUENCE {
       version                   Version,
       privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
       privateKey                PrivateKey,
       attributes            [0] Attributes OPTIONAL,
       ...,
       [[2: publicKey        [1] PublicKey OPTIONAL ]],
       ...
     }
  ...
  PrivateKey ::= OCTET STRING
                        -- Content varies based on type of key.  The
                        -- algorithm identifier dictates the format of
                        -- the key.
~~~
{: artwork-name="RFC5958-OneAsymmetricKey-asn.1-structure"}


When a `CompositeSignaturePrivateKey` is conveyed inside a OneAsymmetricKey structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the privateKeyAlgorithm field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}} and its parameters field MUST be absent. The privateKey field SHALL contain the `CompositeSignaturePrivateKey`, and the `publicKey` field remains OPTIONAL.  If the `publicKey` field is present, it MUST be a `CompositeSignaturePublicKey`.

Some applications may need to reconstruct the `OneAsymmetricKey` objects corresponding to each component private key. {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction.

Component keys of a CompositeSignaturePrivateKey MUST NOT be used in any other type of key or as a standalone key.  For more details on the security considerations around key reuse, see section {{sec-cons-key-reuse}}.


## Encoding Rules {#sec-encoding-rules}
<!-- EDNOTE 7: Examples of how other specifications specify how a data structure is converted to a bit string can be found in RFC 2313, section 10.1.4, 3279 section 2.3.5, and RFC 4055, section 3.2. -->

Many protocol specifications will require that the composite public key and composite private key data structures be represented by an octet string or bit string.

When an octet string is required, the DER encoding of the composite data structure SHALL be used directly.

~~~ ASN.1
CompositeSignaturePublicKeyOs ::= OCTET STRING
                (CONTAINING CompositeSignaturePublicKey ENCODED BY der)
~~~

When a bit string is required, the octets of the DER encoded composite data structure SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

~~~ ASN.1
CompositeSignaturePublicKeyBs ::= BIT STRING
                (CONTAINING CompositeSignaturePublicKey ENCODED BY der)
~~~

In the interests of simplicity and avoiding compatibility issues, implementations that parse these structures MAY accept both BER and DER.

## Key Usage Bits

When any of the Composite ML-DSA `AlgorithmIdentifier` appears in the `SubjectPublicKeyInfo` field of an X.509 certificate [RFC5280], the key usage certificate extension MUST only contain only signing-type key usages.

The normal keyUsage rules for signing-type keys from [RFC5280] apply, and are reproduced here for completeness.

For Certification Authority (CA) certificates that carry a composite public key, any combination of the following values MAY be present and any other values MUST NOT be present:

~~~
digitalSignature;
nonRepudiation;
keyCertSign; and
cRLSign.
~~~

For End Entity certificates, any combination of the following values MAY be present and any other values MUST NOT be present:

~~~
digitalSignature; and
nonRepudiation;
~~~

Composite ML-DSA keys MUST NOT be used in a "dual usage" mode because even if the
traditional component key supports both signing and encryption,
the post-quantum algorithms do not and therefore the overall composite algorithm does not.

# Composite Signature Structures

## sa-CompositeSignature {#sec-composite-sig-structs}

The ASN.1 algorithm object for a composite signature is:

~~~ asn.1
sa-CompositeSignature{OBJECT IDENTIFIER:id,
   PUBLIC-KEY:publicKeyType }
      SIGNATURE-ALGORITHM ::=  {
         IDENTIFIER id
         VALUE CompositeSignatureValue
         PARAMS ARE absent
         PUBLIC-KEYS {publicKeyType}
      }
~~~

## CompositeSignatureValue {#sec-compositeSignatureValue}

The output of a Composite ML-DSA algorithm is the DER encoding of the following structure:


The `CompositeSignatureValue` is the DER encoing of a SEQUENCE of the signature values from the
underlying component algorithms.  It is represented in ASN.1 as follows:

~~~ asn.1
CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
~~~
{: artwork-name="composite-sig-asn.1"}

The order of the component signature values is the same as the order defined in {{sec-composite-pub-keys}}.


# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the list of Composite ML-DSA algorithms and lists the OID and the two component algorithms. Domain separator values are defined below in {{sec-domsep-values}}.

EDNOTE: these are prototyping OIDs to be replaced by IANA.

&lt;CompSig&gt;.1 is equal to 2.16.840.1.114027.80.8.1.1

## Composite-ML-DSA Algorithm Identifiers

Pure Composite-ML-DSA Signature public key types:

| Composite Signature AlgorithmID | OID | First AlgorithmID | Second AlgorithmID |
| ----------- | ----------- | ----------- |  ----------- |
| id-MLDSA44-RSA2048-PSS      | &lt;CompSig&gt;.21 | id-ML-DSA-44  | id-RSASA-PSS with id-sha256 |
| id-MLDSA44-RSA2048-PKCS15    | &lt;CompSig&gt;.22 | id-ML-DSA-44  | sha256WithRSAEncryption |
| id-MLDSA44-Ed25519                  | &lt;CompSig&gt;.23 | id-ML-DSA-44  | id-Ed25519 |
| id-MLDSA44-ECDSA-P256        | &lt;CompSig&gt;.24 | id-ML-DSA-44  | ecdsa-with-SHA256 with secp256r1 |
| id-MLDSA65-RSA3072-PSS          | &lt;CompSig&gt;.26 | id-ML-DSA-65 | id-RSASA-PSS with id-sha256 |
| id-MLDSA65-RSA3072-PKCS15       | &lt;CompSig&gt;.27  | id-ML-DSA-65 | sha256WithRSAEncryption |
| id-MLDSA65-RSA4096-PSS         | &lt;CompSig&gt;.34 | id-ML-DSA-65 | id-RSASA-PSS with id-sha384 |
| id-MLDSA65-RSA4096-PKCS15        | &lt;CompSig&gt;.35  | id-ML-DSA-65 | sha384WithRSAEncryption |
| id-MLDSA65-ECDSA-P384           | &lt;CompSig&gt;.28  | id-ML-DSA-65 | ecdsa-with-SHA384 with secp384r1 |
| id-MLDSA65-ECDSA-brainpoolP256r1 | &lt;CompSig&gt;.29  | id-ML-DSA-65 | ecdsa-with-SHA256 with brainpoolP256r1 |
| id-MLDSA65-Ed25519                      | &lt;CompSig&gt;.30  | id-ML-DSA-65 | id-Ed25519 |
| id-MLDSA87-ECDSA-P384            | &lt;CompSig&gt;.31  | id-ML-DSA-87 | ecdsa-with-SHA384 with secp384r1 |
| id-MLDSA87-ECDSA-brainpoolP384r1 | &lt;CompSig&gt;.32 | id-ML-DSA-87 | ecdsa-with-SHA384 with brainpoolP384r1 |
| id-MLDSA87-Ed448                        | &lt;CompSig&gt;.33 | id-ML-DSA-87 | id-Ed448 |
{: #tab-sig-algs title="Pure ML-DSA Composite Signature Algorithms"}

See the ASN.1 module in section {{sec-asn1-module}} for the explicit definitions of the above Composite ML-DSA algorithms.

Full specifications for the referenced algorithms can be found in {{appdx_components}}.

## HashComposite-ML-DSA Algorithm Identifiers

HashComposite-ML-DSA Signature public key types:

| Composite Signature AlgorithmID | OID | First AlgorithmID | Second AlgorithmID | Pre-Hash |
| ----------- | ----------- | ----------- |  ----------- | ----------- |
| id-HashMLDSA44-RSA2048-PSS-SHA256      | &lt;CompSig&gt;.40 | id-ML-DSA-44  | id-RSASA-PSS with id-sha256 | id-sha256 |
| id-HashMLDSA44-RSA2048-PKCS15-SHA256    | &lt;CompSig&gt;.41 | id-ML-DSA-44  | sha256WithRSAEncryption | id-sha256 |
| id-HashMLDSA44-Ed25519-SHA512             | &lt;CompSig&gt;.42 | id-ML-DSA-44  | id-Ed25519 | id-sha512 |
| id-HashMLDSA44-ECDSA-P256-SHA256         | &lt;CompSig&gt;.43 | id-ML-DSA-44  | ecdsa-with-SHA256 with secp256r1 | id-sha256 |
| id-HashMLDSA65-RSA3072-PSS-SHA512           | &lt;CompSig&gt;.44 | id-ML-DSA-65 | id-RSASA-PSS with id-sha256 | id-sha512 |
| id-HashMLDSA65-RSA3072-PKCS15-SHA512        | &lt;CompSig&gt;.45  | id-ML-DSA-65 | sha256WithRSAEncryption | id-sha512 |
| id-HashMLDSA65-RSA4096-PSS-SHA512           | &lt;CompSig&gt;.46 | id-ML-DSA-65 | id-RSASA-PSS with id-sha384 | id-sha512 |
| id-HashMLDSA65-RSA4096-PKCS15-SHA512        | &lt;CompSig&gt;.47  | id-ML-DSA-65 | sha384WithRSAEncryption | id-sha512 |
| id-HashMLDSA65-ECDSA-P384-SHA512            | &lt;CompSig&gt;.48  | id-ML-DSA-65 | ecdsa-with-SHA384 with secp384r1 | id-sha512 |
| id-HashMLDSA65-ECDSA-brainpoolP256r1-SHA512 | &lt;CompSig&gt;.49  | id-ML-DSA-65 | ecdsa-with-SHA256 with brainpoolP256r1 | id-sha512 |
| id-HashMLDSA65-Ed25519-SHA512              | &lt;CompSig&gt;.50  | id-ML-DSA-65 | id-Ed25519 | id-sha512 |
| id-HashMLDSA87-ECDSA-P384-SHA512            | &lt;CompSig&gt;.51  | id-ML-DSA-87 | ecdsa-with-SHA384 with secp384r1 | id-sha512|
| id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512 | &lt;CompSig&gt;.52 | id-ML-DSA-87 | ecdsa-with-SHA384 with brainpoolP384r1 | id-sha512 |
| id-HashMLDSA87-Ed448-SHA512              | &lt;CompSig&gt;.53 | id-ML-DSA-87 | id-Ed448 | id-sha512 |
{: #tab-hash-sig-algs title="Hash ML-DSA Composite Signature Algorithms"}


See the ASN.1 module in {{sec-asn1-module}} for the explicit definitions of the above Composite ML-DSA algorithms.

The Pre-Hash algorithm is used as the PH algorithm in and the DER Encoded OID value of this Hash is used as HashOID for the Message format in step 2 of `HashComposite-ML-DSA.Sign` in section {{sec-hash-comp-sig-sign}} and `HashComposite-ML-DSA.Verify` in {{sec-hash-comp-sig-verify}}.

Full specifications for the referenced algorithms can be found in {{appdx_components}}.

## Domain Separators {#sec-domsep-values}

As mentioned above, the OID input value is used as a domain separator for the Composite Signature Generation and verification process and is the DER encoding of the OID. The following table shows the HEX encoding for each Signature AlgorithmID.

| Composite Signature AlgorithmID | Domain Separator (in Hex encoding)|
| ----------- | ----------- |
| id-MLDSA44-RSA2048-PSS | 060B6086480186FA6B50080115|
| id-MLDSA44-RSA2048-PKCS15 |060B6086480186FA6B50080116|
| id-MLDSA44-Ed25519 |060B6086480186FA6B50080117|
| id-MLDSA44-ECDSA-P256 |060B6086480186FA6B50080118|
| id-MLDSA65-RSA3072-PSS |060B6086480186FA6B5008011A|
| id-MLDSA65-RSA3072-PKCS15 |060B6086480186FA6B5008011B|
| id-MLDSA65-RSA4096-PSS |060B6086480186FA6B50080122|
| id-MLDSA65-RSA4096-PKCS15 |060B6086480186FA6B50080123|
| id-MLDSA65-ECDSA-P384 |060B6086480186FA6B5008011C|
| id-MLDSA65-ECDSA-brainpoolP256r1 |060B6086480186FA6B5008011D|
| id-MLDSA65-Ed25519 |060B6086480186FA6B5008011E|
| id-MLDSA87-ECDSA-P384 |060B6086480186FA6B5008011F|
| id-MLDSA87-ECDSA-brainpoolP384r1 |060B6086480186FA6B50080120|
| id-MLDSA87-Ed448 |060B6086480186FA6B50080121|
{: #tab-sig-alg-oids title="Pure ML-DSA Composite Signature Domain Separators"}

| Composite Signature AlgorithmID | Domain Separator (in Hex encoding)|
| ----------- | ----------- |
| id-HashMLDSA44-RSA2048-PSS-SHA256 | 060B6086480186FA6B50080128|
| id-HashMLDSA44-RSA2048-PKCS15-SHA256 |060B6086480186FA6B50080129|
| id-HashMLDSA44-Ed25519-SHA512 |060B6086480186FA6B5008012A|
| id-HashMLDSA44-ECDSA-P256-SHA256 |060B6086480186FA6B5008012B|
| id-HashMLDSA65-RSA3072-PSS-SHA512 |060B6086480186FA6B5008012C|
| id-HashMLDSA65-RSA3072-PKCS15-SHA512 |060B6086480186FA6B5008012D|
| id-HashMLDSA65-RSA4096-PSS-SHA512 |060B6086480186FA6B5008012E|
| id-HashMLDSA65-RSA4096-PKCS15-SHA512 |060B6086480186FA6B5008012F|
| id-HashMLDSA65-ECDSA-P384-SHA512 |060B6086480186FA6B50080130|
| id-HashMLDSA65-ECDSA-brainpoolP256r1-SHA512 |060B6086480186FA6B50080131|
| id-HashMLDSA65-Ed25519-SHA512 |060B6086480186FA6B50080132|
| id-HashMLDSA87-ECDSA-P384-SHA512 |060B6086480186FA6B50080133|
| id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512 |060B6086480186FA6B50080134|
| id-HashMLDSA87-Ed448-SHA512 |060B6086480186FA6B50080135|
{: #tab-hash-sig-alg-oids title="Hash ML-DSA Composite Signature Domain Separators"}

## Rationale for choices

* Pair equivalent levels.
* NIST-P-384 is CNSA approved [CNSA2.0] for all classification levels.
* 521 bit curve not widely used.

SHA2 is used throughout in order to facilitate implementations that do not have easy access to SHA3 outside of the ML-DSA function.

At the higher security levels of pre-hashed Composite ML-DSA, for example `id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512`, the 384-bit elliptic curve component is used with SHA2-384 is its pre-hash (ie the pre-hash that is considered to be internal to the ECDSA component), yet SHA2-512 is used as the pre-hash for the overall composite because in this case the pre-hash must not weaken the ML-DSA-87 component against a collision attack.

## RSA-PSS Parameters

Use of RSA-PSS [RFC8017] requires extra parameters to be specified, which differ for each security level.


### RSA2048-PSS

The RSA component keys MUST be generated at the 2048-bit security level in order to compliment ML-DSA-44

As with the other composite signature algorithms, when `id-MLDSA44-RSA2048-PSS` and `id-HashMLDSA44-RSA2048-PSS-SHA256` is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLDSA44-RSA2048-PSS` and `id-HashMLDSA44-RSA2048-PSS-SHA256` SHALL instantiate RSA-PSS with the following parameters:

| RSA-PSS Parameter          | Value                      |
| -------------------------- | -------------------------- |
| Mask Generation Function   | mgf1 |
| Mask Generation params     | SHA-256           |
| Message Digest Algorithm   | SHA-256           |
| Salt Length in bits        | 256               |
{: #rsa-pss-params2048 title="RSA-PSS 2048 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017]
* `SHA-256` is defined in [RFC6234].


### RSA3072-PSS

The RSA component keys MUST be generated at the 3072-bit security level in order to compliment ML-DSA-65.

As with the other composite signature algorithms, when `id-MLDSA65-RSA3072-PSS` or `id-HashMLDSA65-RSA3072-PSS-SHA512`  is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLDSA65-RSA3072-PSS` or `id-HashMLDSA65-RSA3072-PSS-SHA512` SHALL instantiate RSA-PSS with the following parameters:

| RSA-PSS Parameter          | Value                      |
| -------------------------- | -------------------------- |
| Mask Generation Function   | mgf1 |
| Mask Generation params     | SHA-256                |
| Message Digest Algorithm   | SHA-256                |
| Salt Length in bits        | 256                    |
{: #rsa-pss-params3072 title="RSA-PSS 3072 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017]
* `SHA-256` is defined in [RFC6234].

### RSA4096-PSS

The RSA component keys MUST be generated at the 4096-bit security level in order to match with ML-DSA-65.

As with the other composite signature algorithms, when `id-MLDSA65-RSA4096-PSS` or `id-HashMLDSA65-RSA4096-PSS-SHA384`  is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLDSA65-RSA4096-PSS` or `id-HashMLDSA65-RSA4096-PSS-SHA384` SHALL instantiate RSA-PSS with the following parameters:

| RSA-PSS Parameter          | Value                      |
| -------------------------- | -------------------------- |
| Mask Generation Function   | mgf1 |
| Mask Generation params     | SHA-384                |
| Message Digest Algorithm   | SHA-384                |
| Salt Length in bits        | 384                    |
{: #rsa-pss-params4096 title="RSA-PSS 4096 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017]
* `SHA-384` is defined in [RFC6234].

<!-- End of Composite Signature Algorithm section -->


# Use in CMS

\[EDNOTE: The convention in LAMPS is to specify algorithms and their CMS conventions in separate documents. Here we have presented them in the same document, but this section has been written so that it can easily be moved to a standalone document.\]

Composite Signature algorithms MAY be employed for one or more recipients in the CMS signed-data content type [RFC5652].

All recommendations for using Composite ML-DSA in CMS are fully aligned with the use of ML-DSA in CMS {{I-D.salter-lamps-cms-ml-dsa}}.
\[EDNOTE: at time of writing, this draft is not aligned with {{I-D.salter-lamps-cms-ml-dsa}} because it uses SHAKE for the digest algorithm. We believe that it should use SHA2, and we are sorting this out between authors. See: https://mailarchive.ietf.org/arch/msg/spasm/yM8kS1kCoizWCMjS8pdcV3IFaDg/\]

## Underlying Components

A compliant implementation MUST support the following algorithms for the SignerInfo `digestAlgorithm` field when the corresponding Composite ML-DSA algorithm is listed in the SignerInfo `signatureAlgorithm` field.  Implementations MAY also support other algorithms for the SignerInfo `digestAlgorithm` and SHOULD use algorithms of equivalent strength or greater.

| Composite Signature AlgorithmID | digestAlgorithm |
| ----------- | ----------- |
| id-MLDSA44-RSA2048-PSS | SHA256 |
| id-MLDSA44-RSA2048-PKCS15 | SHA256 |
| id-MLDSA44-Ed25519 | SHA512 |
| id-MLDSA44-ECDSA-P256         | SHA256 |
| id-MLDSA65-RSA3072-PSS           | SHA512 |
| id-MLDSA65-RSA3072-PKCS15         | SHA512 |
| id-MLDSA65-RSA4096-PSS           | SHA512 |
| id-MLDSA65-RSA4096-PKCS15        | SHA512 |
| id-MLDSA65-ECDSA-P384            | SHA512 |
| id-MLDSA65-ECDSA-brainpoolP256r1 | SHA512 |
| id-MLDSA65-Ed25519              | SHA512 |
| id-MLDSA87-ECDSA-P384            | SHA512|
| id-MLDSA87-ECDSA-brainpoolP384r1 |  SHA512 |
| id-MLDSA87-Ed448              | SHA512 |
{: #tab-cms-shas title="Recommended Composite Signature Digest Algorithms"}

where:

* SHA2 instantiations are defined in [FIPS180].

Note:  The Hash ML-DSA Composite identifiers are not included in this list because the message content is already digested before being passed to the Composite-ML-DSA.Sign() function.

## SignedData Conventions

As specified in CMS [RFC5652], the digital signature is produced from the message digest and the signer's private key. The signature is computed over different values depending on whether signed attributes are absent or present.

When signed attributes are absent, the composite signature is computed over the message digest of the content. When signed attributes are present, a hash is computed over the content using the hash function specified in {{tab-cms-shas}}, and then a message-digest attribute is constructed to contain the resulting hash value, and then the result of DER encoding the set of signed attributes, which MUST include a content-type attribute and a message-digest attribute, and then the composite signature is computed over the DER-encoded output. In summary:

~~~
IF (signed attributes are absent)
   THEN Composite-ML-DSA.Sign(Hash(content))
ELSE message-digest attribute = Hash(content);
   Composite-ML-DSA.Sign(DER(SignedAttributes))
~~~

When using Composite Signatures, the fields in the SignerInfo are used as follows:

digestAlgorithm:
    Per Section 5.3 of [RFC5652], the digestAlgorithm contains the one-way hash function used by the CMS signer.
    To ensure collision resistance, the identified message digest algorithm SHOULD produce a hash
    value of a size that is at least twice the collision strength of the internal commitment hash used by ML-DSA
    component algorithm of the Composite Signature.

signatureAlgorithm:
    The signatureAlgorithm MUST contain one of the the Composite Signature algorithm identifiers as specified in {{tab-cms-shas}}

signature:
    The signature field contains the signature value resulting from the composite signing operation of the specified signatureAlgorithm.

## Certificate Conventions

The conventions specified in this section augment RFC 5280 [RFC5280].

The willingness to accept a composite Signature Algorithm MAY be signaled by the use of the SMIMECapabilities Attribute as specified in Section 2.5.2. of [RFC8551] or the SMIMECapabilities certificate extension as specified in [RFC4262].

The intended application for the public key MAY be indicated in the key usage certificate extension as specified in Section 4.2.1.3 of [RFC5280]. If the keyUsage extension is present in a certificate that conveys a composite Signature public key, then the key usage extension MUST contain only the following value:

~~~
digitalSignature
nonRepudiation
keyCertSign
cRLSign
~~~

The keyEncipherment and dataEncipherment values MUST NOT be present. That is, a public key intended to be employed only with a composite signature algorithm MUST NOT also be employed for data encryption. This requirement does not carry any particular security consideration; only the convention that signature keys be identified with 'digitalSignature','nonRepudiation','keyCertSign' or 'cRLSign' key usages.


## SMIMECapabilities Attribute Conventions

Section 2.5.2 of [RFC8551] defines the SMIMECapabilities attribute to announce a partial list of algorithms that an S/MIME implementation can support. When constructing a CMS signed-data content type [RFC5652], a compliant implementation MAY include the SMIMECapabilities attribute.

The SMIMECapability SEQUENCE representing a composite signature Algorithm MUST include the appropriate object identifier as per {{tab-cms-shas}} in the capabilityID field.


# ASN.1 Module {#sec-asn1-module}

~~~ asn.1

<CODE STARTS>

{::include Composite-MLDSA-2024.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}
IANA is requested to allocate a value from the "SMI Security for PKIX Module Identifier" registry [RFC7299] for the included ASN.1 module, and allocate values from "SMI Security for PKIX Algorithms" to identify the fourteen Algorithms defined within.

##  Object Identifier Allocations
EDNOTE to IANA: OIDs will need to be replaced in both the ASN.1 module and in {{tab-sig-algs}} and {{tab-hash-sig-algs}}.

###  Module Registration - SMI Security for PKIX Module Identifier
-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-Signatures-2023 - id-mod-composite-signatures
-  References: This Document

###  Object Identifier Registrations - SMI Security for PKIX Algorithms

- id-raw-key
  - Decimal: IANA Assigned
  - Description: Designates a public key BIT STRING with no ASN.1 structure.
  - References: This Document

- id-MLDSA44-RSA2048-PSS-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-RSA2048-PSS-SHA256
  - References: This Document

- id-MLDSA44-RSA2048-PKCS15-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-RSA2048-PKCS15-SHA256
  - References: This Document

- id-MLDSA44-Ed25519
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-Ed25519
  - References: This Document

- id-MLDSA44-ECDSA-P256-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-ECDSA-P256-SHA256
  - References: This Document

- id-MLDSA65-RSA3072-PSS-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-RSA3072-PSS-SHA512
  - References: This Document

- id-MLDSA65-RSA3072-PKCS15-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-RSA3072-PKCS15-SHA512
  - References: This Document

- id-MLDSA65-RSA4096-PSS-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-RSA4096-PSS-SHA512
  - References: This Document

- id-MLDSA65-RSA4096-PKCS15-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-RSA4096-PKCS15-SHA512
  - References: This Document

- id-MLDSA65-ECDSA-P384-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-ECDSA-P384-SHA512
  - References: This Document

- id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - References: This Document

- id-MLDSA65-Ed25519
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-Ed25519
  - References: This Document

- id-MLDSA87-ECDSA-P384-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-ECDSA-P384-SHA512
  - References: This Document

- id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - References: This Document

- id-MLDSA87-Ed448
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-Ed448
  - References: This Document

- id-HashMLDSA44-RSA2048-PSS-SHA256
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA44-RSA2048-PSS-SHA256
  - References: This Document

- id-HashMLDSA44-RSA2048-PKCS15-SHA256
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA44-RSA2048-PKCS15-SHA256
  - References: This Document

- id-HashMLDSA44-Ed25519-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA44-Ed25519-SHA512
  - References: This Document

- id-HashMLDSA44-ECDSA-P256-SHA256
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA44-ECDSA-P256-SHA256
  - References: This Document

- id-HashMLDSA65-RSA3072-PSS-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA65-RSA3072-PSS-SHA512
  - References: This Document

- id-HashMLDSA65-RSA3072-PKCS15-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA65-RSA3072-PKCS15-SHA512
  - References: This Document

- id-HashMLDSA65-RSA4096-PSS-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA65-RSA4096-PSS-SHA512
  - References: This Document

- id-HashMLDSA65-RSA4096-PKCS15-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA65-RSA4096-PKCS15-SHA512
  - References: This Document

- id-HashMLDSA65-ECDSA-P384-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA65-ECDSA-P384-SHA512
  - References: This Document

- id-HashMLDSA65-ECDSA-brainpoolP256r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA65-ECDSA-brainpoolP256r1-SHA512
  - References: This Document

- id-HashMLDSA65-Ed25519-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA65-Ed25519-SHA512
  - References: This Document

- id-HashMLDSA87-ECDSA-P384-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA87-ECDSA-P384-SHA512
  - References: This Document

- id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512
  - References: This Document

- id-HashMLDSA87-Ed448-SHA512
  - Decimal: IANA Assigned
  - Description:  id-HashMLDSA87-Ed448-SHA512
  - References: This Document

<!-- End of IANA Considerations section -->

# Security Considerations

## Non-separability and EUF-CMA {#sec-cons-non-separability}

The signature combiner defined in this document is Weakly Non-Separable (WNS), as defined in {{I-D.ietf-pquip-hybrid-signature-spectrums}},  since the forged message `M’` will include the composite domain separator as evidence. The prohibition on key reuse between composite and single-algorithm contexts discussed in {{sec-cons-key-reuse}} further strengthens the non-separability in practice, but does not achieve Strong Non-Separability (SNS) since policy mechanisms such as this are outside the definition of SNS.

Unforgeability properties are somewhat more nuanced. The classic EUF-CMA game is in reference to a pair of algorithms `( Sign(), Verify() )` where the attacker has access to a signing oracle using the `Sign()` and must produce a signature-message pair `(s, m)` that is accepted by the verifier using `Verify()` and where `m` was never signed by the oracle. The pair `( CompositeML-DSA.Sign(), CompositeML-DSA.Verify() )` is EUF-CMA secure so long as at least one component algorithm is EUF-CMA secure. There is a stronger notion of Strong Existential Unforgeability (SUF) in which an attacker is required to produce a new signature to an already-signed message. CompositeML-DSA only achieves SUF security if both components are SUF secure, which is not a useful property; the argument is that if the first component algorithm is not SUF secure then by definition it admits at least one `(s1*, m)` pair where `s1*` was not produced by the honest signer and it then can be combined with an honestly-signed `(s2, m)` signature over the same message `m` to create `( (s1*, s2), m)` which violates SUF for the composite algorithm.

In addition to the classic EUF-CMA game, we should also consider a “cross-protocol” version of the EUF-CMA game that is relevant to hybrids. Specifically, we want to consider a modified version of the EUF-CMA game where the attacker has access to either a signing oracle over the two component algorithms in isolation, Trad.Sign() and ML-DSA.Sign(), and attempts to fraudulently present them as a composite, or where the attacker has access to a composite oracle for signing and then attempts to split the signature back into components and present them to either ML-DSA.Verify() or Trad.Verify(). The latter version bears a resemblance to a stripping attack, which parallel signatures are subject to, but is slightly different in that the cross-protocol EUF-CMA game also considers modification message definition as signed differs from the message the verifier accepts. In contrast stripping attacks consider only removing one component signature and attempting verification under the remaining and the same original message.

In the case of CompositeML-DSA, a specific message forgery exists for a cross-protocol EUF-CMA attack, namely introduced by the prefix construction addition to M. This applies to use of individual component signing oracles with fraudulent presentation of the signature to a composite verification oracle, and use of a composite signing oracle with fraudulent splitting of the signature for presentation to component verification oracle(s) of either ML-DSA.Verify() or Trad.Verify(). In the first case, an attacker with access to signing oracles for the two component algorithms can sign `M’` and then trivially assemble a composite. In the second case, the message `M’` (containing the composite domain separator) can be presented as having been signed by a standalone component algorithm. However, use of the context string for domain separation enables Weak Non-Separability and auditable checks on hybrid use, which is deemed a reasonable trade-off. Moreover and very importantly, the cross-protocol EUF-CMA attack in either direction is foiled if implementors strictly follow the prohibition on key reuse presented in {{sec-cons-key-reuse}} since then there cannot exist simultaneously composite and non-composite signers and verifiers for the same keys. Consequently, following the specification and verification of the policy mechanism, such as a composite X.509 certificate which defines the bound keys, is essential when using keys intended for use with a CompositeML-DSA signing algorithm.


## Key Reuse {#sec-cons-key-reuse}

When using single-algorithm cryptography, the best practice is to always generate fresh key material for each purpose, for example when renewing a certificate, or obtaining both a TLS and S/MIME certificate for the same device, however in practice key reuse in such scenarios is not always catastrophic to security and therefore often tolerated, despite cross-protocol attacks having been shown. (citation needed here)

Within the broader context of PQ / Traditional hybrids, we need to consider new attack surfaces that arise due to the hybrid constructions and did not exist in single-algorithm contexts. One of these is key reuse where the component keys within a hybrid are also used by themselves within a single-algorithm context. For example, it might be tempting for an operator to take an already-deployed RSA key pair and combine it with an ML-DSA key pair to form a hybrid key pair for use in a hybrid algorithm. Within a hybrid signature context this leads to a class of attacks referred to as "stripping attacks" discussed in {{sec-cons-non-separability}} and may also open up risks from further cross-protocol attacks. Despite the weak non-separability property offered by the composite signature combiner, it is still RECOMMENDED to avoid key reuse as key reuse in single-algorithm use cases could introduce EUF-CMA vulnerabilities.

In addition, there is a further implication to key reuse regarding certificate revocation. Upon receiving a new certificate enrollment request, many certification authorities will check if the requested public key has been previously revoked due to key compromise. Often a CA will perform this check by using the public key hash. Therefore, even if both components of a composite have been previously revoked, the CA may only check the hash of the combined composite key and not find the revocations. Therefore, it is RECOMMENDED to avoid key reuse and always generate fresh component keys for a new composite. It is also RECOMMENDED that CAs performing revocation checks on a composite key should also check both component keys independently.


## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key, certificate, or signature contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), then clients performing signatures or verifications should be updated to adhere to appropriate policies.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled independently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLDSA65-ECDSA-P256-SHA512` even after ECDSA-P256 is deprecated.

When considering stripping attacks, one need consider the case where an attacker has fully compromised one of the component algorithms to the point that they can produce forged signatures that appear valid under one of the component public keys, and thus fool a victim verifier into accepting a forged signature. The protection against this attack relies on the victim verifier trusting the pair of public keys as a single composite key, and not trusting the individual component keys by themselves.

Specifically, in order to achieve this non-separability property, this specification makes two assumptions about how the verifier will establish trust in a composite public key:

1. This specification assumes that all of the component keys within a composite key are freshly generated for the composite; ie a given public key MUST NOT appear as a component within a composite key and also within single-algorithm constructions.

2. This specification assumes that composite public keys will be bound in a structure that contains a signature over the public key (for example, an X.509 Certificate [RFC5280]), which is chained back to a trust anchor, and where that signature algorithm is at least as strong as the composite public key that it is protecting.

There are mechanisms within Internet PKI where trusted public keys do not appear within signed structures -- such as the Trust Anchor format defined in [RFC5914]. In such cases, it is the responsibility of implementers to ensure that trusted composite keys are distributed in a way that is tamper-resistant and does not allow the component keys to be trusted independently.


<!-- End of Security Considerations section -->

<!-- Start of Appendices -->

--- back


# Samples {#appdx-samples}

## Explicit Composite Signature Examples {#appdx-expComposite-examples}

TODO - Need Samples

# Component Algorithm Reference {#appdx_components}

This section provides references to the full specification of the algorithms used in the composite constructions.

| Component Signature Algorithm ID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | [FIPS.204] |
| id-ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | [FIPS.204] |
| id-ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | [FIPS.204] |
| id-Ed25519   | 1.3.101.112 | [RFC8410] |
| id-Ed448     | 1.3.101.113 | [RFC8410] |
| ecdsa-with-SHA256 | 1.2.840.10045.4.3.2 | [RFC5758] |
| ecdsa-with-SHA512 | 1.2.840.10045.4.3.4 | [RFC5758] |
| sha256WithRSAEncryption | 1.2.840.113549.1.1.11 | [RFC8017] |
| sha512WithRSAEncryption | 1.2.840.113549.1.1.13 | [RFC8017] |
| id-RSASA-PSS | 1.2.840.113549.1.1.10 | [RFC8017] |
{: #tab-component-sig-algs title="Component Signature Algorithms used in Composite Constructions"}

| Elliptic CurveID | OID | Specification |
| ----------- | ----------- | ----------- |
| secp256r1 | 1.2.840.10045.3.1.7 | [RFC6090] |
| secp384r1 | 1.3.132.0.34 | [RFC6090] |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7 | [RFC5639] |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | [RFC5639] |
{: #tab-component-curve-algs title="Elliptic Curves used in Composite Constructions"}

| HashID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-sha256 | 2.16.840.1.101.3.4.2.1 | [RFC6234] |
| id-sha512 | 2.16.840.1..101.3.4.2.3 | [RFC6234] |
{: #tab-component-hash title="Hash algorithms used in Composite Constructions"}

# Component AlgorithmIdentifiers for Public Keys and Signatures

To ease implementing Composite Signatures this section specifies the Algorithms Identifiers for each component algorithm. They are provided as ASN.1 value notation and copy and paste DER encoding to avoid any ambiguity. Developers may use this information to reconstruct non hybrid public keys and signatures from each component that can be fed to crypto APIs to create or verify a single component signature.

For newer Algorithms like Ed25519 or ML-DSA the AlgorithmIdentifiers are the same for Public Key and Signature. Older Algorithms have different AlgorithmIdentifiers for keys and signatures and are specified separately here for each component.

**ML-DSA-44 -- AlgorithmIdentifier of Public Key and Signature**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ML-DSA-44   -- (2 16 840 1 101 3 4 3 17)
   }

DER:
  30 0B 06 09 60 86 48 01 65 03 04 03 11
~~~


**ML-DSA-65 -- AlgorithmIdentifier of Public Key and Signature**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ML-DSA-65   -- (2 16 840 1 101 3 4 3 18)
   }

DER:
  30 0B 06 09 60 86 48 01 65 03 04 03 12
~~~


**ML-DSA-87 -- AlgorithmIdentifier of Public Key and Signature**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ML-DSA-87   -- (2 16 840 1 101 3 4 3 19)
   }

DER:
  30 0B 06 09 60 86 48 01 65 03 04 03 13
~~~


**RSA PSS 2048 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS   -- (1.2.840.113549.1.1.10)
    }

DER:
  30 0B 06 09 2A 86 48 86 F7 0D 01 01 0A
~~~

**RSA PSS 2048 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signatureAlgorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS,   -- (1.2.840.113549.1.1.10)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm id-sha256,   -- (2.16.840.1.101.3.4.2.1)
        parameters NULL
        },
      AlgorithmIdentifier ::= {
        algorithm id-mgf1,       -- (1.2.840.113549.1.1.8)
        parameters AlgorithmIdentifier ::= {
          algorithm id-sha256,   -- (2.16.840.1.101.3.4.2.1)
          parameters NULL
          }
        },
      saltLength 32
      }
    }

DER:
  30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86
  48 01 65 03 04 02 01 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01
  08 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A2 03 02 01 20
~~~

**RSA PSS 3072 & 4096 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS   -- (1.2.840.113549.1.1.10)
    }

DER:
  30 0B 06 09 2A 86 48 86 F7 0D 01 01 0A
~~~

**RSA PSS 3072 & 4096 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signatureAlgorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS,   -- (1.2.840.113549.1.1.10)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm id-sha512,   -- (2.16.840.1.101.3.4.2.3)
        parameters NULL
        },
      AlgorithmIdentifier ::= {
        algorithm id-mgf1,       -- (1.2.840.113549.1.1.8)
        parameters AlgorithmIdentifier ::= {
          algorithm id-sha512,   -- (2.16.840.1.101.3.4.2.3)
          parameters NULL
          }
        },
      saltLength 64
      }
    }

DER:
  30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86
  48 01 65 03 04 02 03 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01
  08 30 0D 06 09 60 86 48 01 65 03 04 02 03 05 00 A2 03 02 01 40
~~~

**RSA PKCS 1.5 2048 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm rsaEncryption,   -- (1.2.840.113549.1.1.1)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
~~~

**RSA PKCS 1.5 2048 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signatureAlgorithm AlgorithmIdentifier ::= {
    algorithm sha256WithRSAEncryption,   -- (1.2.840.113549.1.1.11)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 0D 05 00
~~~

**RSA PKCS 1.5 3072 & 4096 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm rsaEncryption,   -- (1.2.840.113549.1.1.1)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
~~~

**RSA PKCS 1.5 3072 & 4096 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signatureAlgorithm AlgorithmIdentifier ::= {
    algorithm sha512WithRSAEncryption,   -- (1.2.840.113549.1.1.13)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 0D 05 00
~~~

**ECDSA NIST 256 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm secp256r1   -- (1.2.840.10045.3.1.7)
        }
      }
    }

DER:
  30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07
~~~

**ECDSA NIST 256 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA256   -- (1.2.840.10045.4.3.2)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 02
~~~

**ECDSA NIST-384 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm secp384r1   -- (1.3.132.0.34)
        }
      }
    }

DER:
  30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22
~~~

**ECDSA NIST-384 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA384   -- (1.2.840.10045.4.3.3)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 03
~~~

**ECDSA Brainpool-256 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm brainpoolP256r1   -- (1.3.36.3.3.2.8.1.1.7)
        }
      }
    }

DER:
  30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 07
~~~

**ECDSA Brainpool-256 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA256   -- (1.2.840.10045.4.3.2)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 02
~~~

**ECDSA Brainpool-384 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm brainpoolP384r1   -- (1.3.36.3.3.2.8.1.1.11)
        }
      }
    }

DER:
  30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0B
~~~

**ECDSA Brainpool-384 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA384   -- (1.2.840.10045.4.3.3)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 03
~~~

**Ed25519 -- AlgorithmIdentifier of Public Key and Signature**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-Ed25519   -- (1.3.101.112)
    }

DER:
  30 05 06 03 2B 65 70
~~~

**Ed448 -- AlgorithmIdentifier of Public Key and Signature**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-Ed448   -- (1.3.101.113)
    }

DER:
  30 05 06 03 2B 65 71
~~~


# Implementation Considerations {#sec-imp-considers}

## FIPS certification {#sec-fips}

One of the primary design goals of this specification is for the overall composite algorithm to be able to be considered FIPS-approved even when one of the component algorithms is not.

Implementors seeking FIPS certification of a composite Signature algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorithm with zero security, and the overall composite should be considered at least as strong and thus FIPS-approved.

The authors wish to note that this gives composite algorithms great future utility both for future cryptographic migrations as well as bridging across jurisdictions, for example defining composite algorithms which combine FIPS cryptography with cryptography from a different national standards body.


## Backwards Compatibility {#sec-backwards-compat}

The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can interoperate with the upgraded systems of the future.  This draft explicitly does not provide backwards compatibility, only upgraded systems will understand the OIDs defined in this document.

If backwards compatibility is required, then additional mechanisms will be needed.  Migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to digital signature objects, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], document signing such as in the context of the European eIDAS regulations [eIDAS2014], and publicly trusted code signing [codeSigningBRsv2.8], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] signed structures.  Composite simplifies the protocol design work because it can be implemented as a signature algorithm that fits into existing systems.

### Hybrid Extensions (Keys and Signatures)

The use of Composite Crypto provides the possibility to process multiple algorithms without changing the logic of applications but updating the cryptographic libraries: one-time change across the whole system. However, when it is not possible to upgrade the crypto engines/libraries, it is possible to leverage X.509 extensions to encode the additional keys and signatures. When the custom extensions are not marked critical, although this approach provides the most backward-compatible approach where clients can simply ignore the post-quantum (or extra) keys and signatures, it also requires all applications to be updated for correctly processing multiple algorithms together.


<!-- End of Implementation Considerations section -->



# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/


# Contributors and Acknowledgements
This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past few years in pursuit of this document:

Daniel Van Geest (CryptoNext),
Dr. Britta Hale (Naval Postgraduade School),
Tim Hollebeek (Digicert),
Panos Kampanakis (Cisco Systems),
Richard Kisley (IBM),
Serge Mister (Entrust),
Piotr Popis,
François Rousseau,
Falko Strenzke,
Felipe Ventura (Entrust),
Alexander Ralien (Siemens),
José Ignacio Escribano,
Jan Oupický,
陳志華 (Abel C. H. Chen, Chunghwa Telecom),
林邦曄 (Austin Lin, Chunghwa Telecom) and
Mojtaba Bisheh-Niasar

We especially want to recognize the contributions of Dr. Britta Hale who has helped immensely with strengthening the signature combiner construction, and with analyzing the scheme with respect to EUF-CMA and Non-Separability properties.

We are grateful to all who have given feedback over the years, formally or informally, on mailing lists or in person, including any contributors who may have been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].

## Making contributions

Additional contributions to this draft are welcome. Please see the working copy of this draft at, as well as open issues at:

https://github.com/lamps-wg/draft-composite-sigs

<!-- End of Contributors section -->
