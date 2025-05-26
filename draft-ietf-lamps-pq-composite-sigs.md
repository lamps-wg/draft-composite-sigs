---
title: Composite ML-DSA for use in X.509 Public Key Infrastructure and CMS
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
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    date: May 21, 2009
    author:
      org: "Certicom Research"
    target: https://www.secg.org/sec1-v2.pdf
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    date: January 27, 2010
    author:
      org: "Certicom Research"
    target: https://www.secg.org/sec2-v2.pdf
  X9.62–2005:
    title: "Public Key Cryptography for the Financial Services Industry The Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: "November 16, 2005"
    author:
      org: "American National Standards Institute"
  FIPS.186-5:
    title: "Digital Signature Standard (DSS)"
    date: February 3, 2023
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
  FIPS.202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    date: August 2015
    author:
      org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
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
  I-D.draft-ietf-pquip-pqt-hybrid-terminology-04:
  I-D.draft-ietf-lamps-dilithium-certificates-04:
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
  CNSA2.0:
      title: "Commercial National Security Algorithm Suite 2.0"
      org: National Security Agency
      target: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
  eIDAS2014:
    title: "Regulation (EU) No 910/2014 of the European Parliament and of the Council of 23 July 2014 on electronic identification and trust services for electronic transactions in the internal market and repealing Directive 1999/93/EC"
    org: European Parliament and Council
    target: https://eur-lex.europa.eu/eli/reg/2014/910/oj/eng
  codesigningbrsv3.8:
    title: "Baseline Requirements for the Issuance and Management of Publicly‐Trusted Code Signing Certificates Version 3.8.0"
    org: CA/Browser Forum
    target: https://cabforum.org/working-groups/code-signing/documents/




--- abstract

This document defines combinations of ML-DSA [FIPS.204] in hybrid with traditional algorithms RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, Ed25519, and Ed448. These combinations are tailored to meet security best practices and regulatory requirements. Composite ML-DSA is applicable in any application that uses X.509 or PKIX data structures that accept ML-DSA, but where the operator wants extra protection against breaks or catastrophic bugs in ML-DSA.

<!-- End of Abstract -->


--- middle


# Changes in -05

Interop-affecting changes:

* MAJOR CHANGE: Authors decided to remove all "pure" composites and leave only the pre-hashed variants (which were renamed to simply be "Composite" instead of "HashComposite"). The core construction of the Mprime construction was not modified, simply re-named. This results in a ~50% reduction in the length of the draft since we removed ~50% of the content. This is the result of long design discussions, some of which is captured in https://github.com/lamps-wg/draft-composite-sigs/issues/131
* Adjusted the choice of pre-hash function for Ed448 to SHAKE256/64 to match the hash functions used in ED448ph in RFC8032.
* ML-DSA secret keys are now only seeds.
* Since all ML-DSA keys and signatures are now fixed-length, dropped the length-tagged encoding.
* Added new prototype OIDs to avoid interoperability issues with previous versions
* Added complete test vectors.

Editorial changes:

* Since the serialization is now non-DER, drastically reduced the ASN.1-based text.

Still to do in a future version:

- `[ ]` Other outstanding github issues: https://github.com/lamps-wg/draft-composite-sigs/issues

# Introduction {#sec-intro}

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic algorithms such as RSA, Diffie-Hellman, DSA, and their elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify potential implementation flaws.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward. Even after the migration period, it may be advantageous for an entity's cryptographic identity to incorporate multiple public-key algorithms to enhance security.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.ietf-pquip-pqt-hybrid-terminology}}.  Combining multiple algorithms  can help to eliminate single points of failure, where a component algorithm is a technology that may fail in the future.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of Composite scheme provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies [BSI2021].

Some jursidictions may prefer or impose the use of different algorithms.  Combining algorithms from different jurisdictions could provide a way to communicate between jurisdictions with different algorithm requirements.

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


Notation:
The algorithm descriptions use python-like syntax. The following symbols deserve special mention:

 * `||` represents concatenation of two byte arrays.

 * `[:]` represents byte array slicing.

 * `(a, b)` represents a pair of values `a` and `b`. Typically this indicates that a function returns multiple values; the exact conveyance mechanism -- tuple, struct, output parameters, etc -- is left to the implementer.


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
      as input a secret key sk and a Message, and outputs a signature.

   *  `Verify(pk, Message, signature) -> true or false`: A verification algorithm
      which takes as input a public key, a Message, and a signature and outputs true
      if the signature verifies correctly.  Thus it proves the Message was signed
      with the secret key associated with the public key and verifies the integrity
      of the Message.  If the signature and public key cannot verify the Message,
      it returns false.

We define the following algorithms which we use to serialize and deserialize the public and private keys

   *  `SerializeKey(key) -> bytes`: Produce a byte string encoding the public or private key.

   *  `DeserializeKey(bytes) -> pk`: Parse a byte string to recover a public or private key. This function can fail if the input byte string is malformed.

We define the following algorithms which are used to serialize and deseralize the composite signature value

   *  `SerializeSignatureValue(CompositeSignatureValue) -> bytes`: Produce a byte string encoding the CompositeSignatureValue.

   *  `DeserializeSignatureValue(bytes) -> signature`: Parse a byte string to recover a CompositeSignatureValue. This function can fail if the input byte string is malformed.

A composite signature allows the security properties of the two underlying algorithms to be combined via standard signature operations `Sign()` and `Verify()`.

This specification uses the Post-Quantum signature scheme ML-DSA as specified in [FIPS.204] and {{I-D.ietf-lamps-dilithium-certificates}}. For Traditional signature schemes, this document uses the RSASSA-PKCS1-v1_5 and RSASSA-PSS algorithms defined in [RFC8017], the Elliptic Curve Digital Signature Algorithm ECDSA scheme defined in section 6 of [FIPS.186-5], and Ed25519 / Ed448 which are defined in [RFC8410]. A simple "signature combiner" function which prepends a domain separator value specific to the composite algorithm is used to bind the two component signatures to the composite algorithm and achieve weak non-separability.

## Pure vs Pre-hashed modes

In [FIPS.204] NIST defined ML-DSA to have both pure and pre-hashed signing modes, referred to as "ML-DSA" and "HashML-DSA" respectively. Following this, this document defines "Composite-ML-DSA" which uses a strong hash function in the Message format, and makes use of the pure "ML-DSA" mode as the underlying ML-DSA mode. This gives Composite ML-DSA a balance between performance and security.


## Domain Separators and CTX {#sec-domsep-and-ctx}

In CompositeML-DSA, the Domain separator defined in {{sec-domsep-values}} is concatenated with the length of the context in bytes, the context, an additional DER encoded value that represents the OID of the Hash function and finally the hash of the message to be signed.  After that, the signature process for each component algorithm is invoked and the values are serialized into a composite signature value as per {{sec-serialize-sig}}.

A composite signature's value MUST include two signature components and MUST be in the same order as the components from the corresponding signing key.

Note that there are two different context strings `ctx` here: the first is the application context that is passed in to `Composite.Sign` and bound to the composite signature combiner. The second is the `ctx` that is passed down into the underlying `ML-DSA.Sign` and here Composite-ML-DSA itself is the application that we wish to bind, and outer `ctx` is already contained within the `M'` message.


# Composite Functions {#sec-sigs}

## Composite Key Generation


In order to maintain security properties of the composite, applications that use composite keys MUST always perform fresh key generations of both component keys and MUST NOT reuse existing key material. See {{sec-cons-key-reuse}} for a discussion.

To generate a new keypair for Composite schemes, the `KeyGen() -> (pk, sk)` function is used. The KeyGen() function calls the two key generation functions of the component algorithms for the Composite keypair in no particular order. Multi-process or multi-threaded applications might choose to execute the key generation functions in parallel for better key generation performance.

The following process is used to generate composite keypair values:

~~~
KeyGen() -> (pk, sk)

Explicit inputs:

  None

Implicit inputs:

  FirstAlg   The first algorithm and parameter set, for example, could be "ML-DSA-65".

  SecondAlg  The second algorithm and parameter set, for example "RSASSA-PSS"
             or "Ed25519".

Output:

  (pk, sk)   The composite keypair.

Key Generation Process:

  1. Generate component keys

      (firstPK, firstSK) = FirstAlg.KeyGen()
      (secondPK, secondSK)   = SecondAlg.KeyGen()

  2. Check for component key gen failure

      if NOT (firstPK, firstSK) or NOT (secondPK, secondSK):
        output "Key generation error"

  3. Output the composite public and private keys

    pk = firstPK || secondPK
    sk = firstSK || secondSK
    return (pk, sk)

~~~
{: #alg-composite-keygen title="Composite KeyGen(pk, sk)"}

In order to ensure fresh keys, the key generation functions MUST be executed for both component algorithms. Compliant parties MUST NOT use, import or export component keys that are used in other contexts, combinations, or by themselves as keys for standalone algorithm use. For more details on the security considerations around key reuse, see section {{sec-cons-key-reuse}}.

Note that in step 2 above, both component key generation processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.


## Sign {#sec-hash-comp-sig-sign}

This mode mirrors `HashML-DSA.Sign(sk, M, ctx, PH)` defined in Algorithm 4 Section 5.4.1 of [FIPS.204].

In CompositeML-DSA, the Domain separator (see {{sec-domsep-values}}) is concatenated with the length of the context in bytes, the context, an additional DER encoded value that indicates which Hash function was used for the pre-hash and finally the pre-hashed message `PH(M)`.

~~~
Composite.Sign (sk, M, ctx, PH) -> (signature)

Explicit inputs:

  sk    Composite private key consisting of signing private keys for
        each component.

  M     The Message to be signed, an octet string.

  ctx   The Message context string used in the composite signature
        combiner, which defaults to the empty string.

  PH    The Message Digest Algorithm for pre-hashing.  See
        section on pre-hashing the message below.

Implicit inputs:

FirstAlg   The first algorithm and parameter set, for example,
           could be "ML-DSA-65".

SecondAlg  The second algorithm and parameter set, for example
           "RSASSA-PSS with id-sha256" or "Ed25519".

 Prefix    The prefix String which is the byte encoding of the String
           "CompositeAlgorithmSignatures2025" which in hex is
           436F6D706F73697465416C676F726974686D5369676E61747572657332303235

 Domain    Domain separator value for binding the signature to the
           Composite OID. See section on Domain Separators below.

 HashOID   The DER Encoding of the Object Identifier of the
           PreHash algorithm (PH) which is passed into the function.

Output:
  signature   The composite signature, a CompositeSignatureValue.

Signature Generation Process:

  1. If len(ctx) > 255:
      return error

  2. Compute the Message format M'.
     As in FIPS 204, len(ctx) is encoded as a single unsigned byte.

        M' :=  Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)

  3. Separate the private key into component keys
     and re-generate the ML-DSA key from seed.

       (firstSK, secondSK) = DeserializePrivateKey(sk)
       firstSK = FirstAlg.init(firstSK)
       secondSK = SecondAlg.init(secondSK) 

  4. Generate the 2 component signatures independently, by calculating
     the signature over M' according to their algorithm specifications.

       If FirstAlg supports context:
          firstSig = FirstAlg.Sign( firstSK, M', ctx=Domain )
       else
          firstSig = FirstAlg.Sign( firstSK, M')

       If SecondAlg supports context:
          secondSig = SecondAlg.Sign( secondSK, M', ctx=Domain )
       else
          secondSig = SecondALg.Sign( secondSK, M' )

  5. If either FirstAlg.Sign() or SecondAlg.Sign() return an error, then this
     process must return an error.

      if NOT firstSig or NOT secondSig:
        output "Signature generation error"

  6. Encode each component signature into a CompositeSignatureValue.

      signature = firstSig || secondSig

  7. Output signature

      return signature
~~~
{: #alg-composite-sign title="Composite.Sign(sk, M, ctx, PH)"}

It is possible to use component private keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this document so long as it produces the same output and error handling as the process sketched above.

Note that in step 5 above, both component signature processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

Note that there are two different context strings `ctx` here: the first is the application context that is passed in to `Composite.Sign` and bound to the composite signature combiner. The second is the `ctx` that is passed down into the underlying `ML-DSA.Sign` and here Composite-ML-DSA itself is the application that we wish to bind, and outer `ctx` is already contained within the `M'` message.


## Verify {#sec-hash-comp-sig-verify}

This mode mirrors `HashML-DSA.Verify(pk, M, signature, ctx, PH)` defined in Algorithm 5 Section 5.4.1 of [FIPS.204].

Compliant applications MUST output "Valid signature" (true) if and only if all component signatures were successfully validated, and "Invalid signature" (false) otherwise.

~~~
Composite.Verify(pk, M, signature, ctx, PH)

Explicit inputs:

  pk          Composite public key consisting of verification public
              keys for each component.

  M           Message whose signature is to be verified, an octet
              string.

  signature   CompositeSignatureValue containing the component
              signature values (mldsaSig and tradSig) to be verified.

  ctx         The Message context string used in the composite signature
              combiner, which defaults to the empty string.

  PH          The Message Digest Algorithm for pre-hashing. See
              section on pre-hashing the message below.

Implicit inputs:

  ML-DSA    The underlying ML-DSA algorithm and
            parameter set, for example, could be "ML-DSA-65".

  Trad      The underlying traditional algorithm and
            parameter set, for example "RSASSA-PSS with id-sha256"
            or "Ed25519".

  Prefix    The prefix String which is the byte encoding of the String
            "CompositeAlgorithmSignatures2025" which in hex is
            436F6D706F73697465416C676F726974686D5369676E61747572657332303235

  Domain    Domain separator value for binding the signature to the
            Composite OID. See section on Domain Separators below.

  HashOID   The DER Encoding of the Object Identifier of the
            PreHash algorithm (PH) which is passed into the function.

Output:

  Validity (bool)   "Valid signature" (true) if the composite
                    signature is valid, "Invalid signature"
                    (false) otherwise.

Signature Verification Process:

  1. If len(ctx) > 255
       return error

  2. Separate the keys and signatures

     (pk1, pk2) = DeserializePublicKey(pk)
     (s1, s2)   = DeserializeSignatureValue(signature)

   If Error during Desequencing, or if any of the component
   keys or signature values are not of the correct key type or
   length for the given component algorithm then output
   "Invalid signature" and stop.

  3. Compute a Hash of the Message.
     As in FIPS 204, len(ctx) is encoded as a single unsigned byte.

      M' = Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)

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
{: #alg-composite-verify title="Composite.Verify(pk, M, signature, ctx, PH)"}

Note that in step 4 above, the function fails early if the first component fails to verify. Since no private keys are involved in a signature verification, there are no timing attacks to consider, so this is ok.

Note that there are two different context strings `ctx` here: the first is the application context that is passed in to `Composite.Sign` and bound to the composite signature combiner. The second is the `ctx` that is passed down into the underlying `ML-DSA.Sign` and here Composite-ML-DSA itself is the application that we wish to bind, and outer `ctx` is already contained within the `M'` message.


# Serialization {#sec-serialization}

This section presents routines for serializing and deserializing composite public keys, private keys (seeds), and signature values to bytes via simple concatenation of the underlying encodings of the component algorithms.
Deserialization is possible because ML-DSA has fixed-length public keys, private keys (seeds), and signature values as shown in the following table.

| Algorithm | Public key  | Private key | Signature |
| --------- | ----------- | ----------- |  -------- |
| ML-DSA-44 |     1312    |      32     |    2420   |
| ML-DSA-65 |     1952    |      32     |    3309   |
| ML-DSA-87 |     2592    |      32     |    4627   |
{: #tab-mldsa-sizes title="ML-DSA Key and Signature Sizes in bytes"}

When these values are required to be carried in an ASN.1 structure, they are wrapped as described in {{sec-encoding-to-der}}.

While ML-DSA has a single fixed-size representation for each of public key, private key (seed), and signature, the traditional component might allow multiple valid encodings; for example an elliptic curve public key might be validly encoded as either compressed or uncompressed [SEC1], or an RSA private key could be encoded in Chinese Remainder Theorem form [RFC8017]. In order to obtain interoperability, composite algorithms MUST use the following encodings of the underlying components:

* **ML-DSA**: MUST be encoded as specified in [FIPS204], using a 32-byte seed as the private key.
* **RSA**: MUST be encoded with the `(n,e)` public key representation as specified in A.1.1 of [RFC8017] and the private key representation as specified in A.1.2 of [RFC8017].
* **ECDSA**: MUST be encoded as an `ECPoint` as specified in section 2.2 of [RFC5480], with both compressed and uncompressed keys supported. For maximum interoperability, it is RECOMMENEDED to use uncompressed points.
* **EdDSA**: MUST be encoded as per section 3.1 of [RFC8032] and section 4 of [RFC8410].

In the event that a composite implementation uses an underlying implementation of the traditional component that requires a different encoding, it is the responsibility of the composite implementation to perform the necessary transcoding. Even with fixed encodings for the traditional component, there may be slight differences in encoded size of the traditional component due to, for example, encoding rules that drop leading zeroes. See {{sec-sizetable}} for further discussion of encoded size of each composite algorithm.

### SerializePublicKey and DeserializePublicKey {#sec-serialize-pubkey}

The serialization routine for keys simply concatenates the fixed-length public keys of the component signature algorithms, as defined below:

~~~
Composite.SerializePublicKey(mldsaPK, tradPK) -> bytes

Explicit Input:

  mldsaPK  The ML-DSA public key, which is bytes.

  tradPK   The traditional public key in the appropriate
           bytes-like encoding for the underlying component algorithm.

Output:

  bytes   The encoded composite public key

Serialization Process:

  1. Combine and output the encoded public key

     output mldsaPK || tradPK
~~~
{: #alg-composite-serialize-pk title="SerializePublicKey(mldsaPK, tradPK) -> bytes"}


Deserialization reverses this process, raising an error in the event that the input is malformed.  Each component key is deserialized according to their respective standard as shown in {{appdx_components}}.

~~~
Composite.DeserializePublicKey(bytes) -> (mldsaKey, tradKey)

Explicit Input:

  bytes   An encoded composite public key

Implicit inputs:

  ML-DSA   A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example, could be "ML-DSA-65".

Output:

  mldsaPK  The ML-DSA public key, which is bytes.

  tradPK   The traditional public key in the appropriate
           bytes-like encoding for the underlying component algorithm.

Deserialization Process:

  1. Parse each constituent encoded public key.
       The length of the mldsaKey is known based on the size of
       the ML-DSA component key length specified by the Object ID

     switch ML-DSA do
        case ML-DSA-44:
          mldsaPK = bytes[:1312]
          tradPK  = bytes[1312:]
        case ML-DSA-65:
          mldsaPK = bytes[:1952]
          tradPK  = bytes[1952:]
        case ML-DSA-87:
          mldsaPK = bytes[:2592]
          tradPK  = bytes[2592:]

     Note that while ML-DSA has fixed-length keys, RSA and ECDH
     may not, depending on encoding, so rigorous length-checking
     of the overall composite key is not always possible.

  2. Output the component public keys

     output (mldsaPK, tradPK)
~~~
{: #alg-composite-deserialize-pk title="DeserializePublicKey(bytes) -> (mldsaPK, tradPK)"}



## SerializePrivateKey and DeserializePrivateKey {#sec-serialize-privkey}

The serialization routine for keys simply concatenates the fixed-length private keys of the component signature algorithms, as defined below:

~~~
Composite.SerializePrivateKey(mldsaSeed, tradSK) -> bytes

Explicit Input:

  mldsaSeed  The ML-DSA private key, which is the bytes of the seed.

  tradSK     The traditional private key in the appropriate
             encoding for the underlying component algorithm.

Output:

  bytes   The encoded composite private key

Serialization Process:

  1. Combine and output the encoded private key

     output mldsaSeed || tradSK
~~~
{: #alg-composite-serialize-sk title="SerializePrivateKey(mldsaSeed, tradSK) -> bytes"}


Deserialization reverses this process, raising an error in the event that the input is malformed.

~~~
Composite.DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)

Explicit Input:

  bytes   An encoded composite private key

Output:

  mldsaSeed  The ML-DSA private key, which is the bytes of the seed.

  tradSK     The traditional private key in the appropriate
             encoding for the underlying component algorithm.

Deserialization Process:

  1. Parse each constituent encoded key.
       The length of an ML-DSA private key is always a 32 byte seed
       for all parameter sets.

      mldsaSeed = bytes[:32]
      tradSK  = bytes[32:]

     Note that while ML-KEM has fixed-length keys (seeds), RSA and ECDH
     may not, depending on encoding, so rigorous length-checking
     of the overall composite key is not always possible.

  2. Output the component private keys

     output (mldsaSeed, tradSK)
~~~
{: #alg-composite-deserialize-sk title="DeserializeKey(bytes) -> (mldsaSeed, tradSK)"}



## SerializeSignatureValue and DeserializeSignatureValue {#sec-serialize-sig}

The serialization routine for the CompositeSignatureValue simply concatenates the fixed-length
ML-DSA signature value with the signature value from the traditional algorithm, as defined below:

~~~
Composite.SerializeSignatureValue(mldsaSig, tradSig) -> bytes

Explicit Inputs:

  mldsaSig  The ML-DSA signature value, which is bytes.

  tradSig   The traditional signature value in the appropriate
            encoding for the underlying component algorithm.

Output:

  bytes   The encoded CompositeSignatureValue

Serialization Process:

  1. Combine and output the encoded composite signature

     output mldsaSig || tradSig

~~~
{: #alg-composite-serialize-sig title="SerializeSignatureValue(mldsaSig, tradSig) -> bytes"}


Deserialization reverses this process, raising an error in the event that the input is malformed.  Each component signature is deserialized according to their respective standard as shown in {{appdx_components}}.

~~~
Composite.DeserializeSignatureValue(bytes) -> (mldsaSig, tradSig)

Explicit Input:

  bytes   An encoded CompositeSignatureValue

Implicit inputs:

  ML-DSA   A placeholder for the specific ML-DSA algorithm and
           parameter set to use, for example, could be "ML-DSA-65".

Output:

  mldsaSig  The ML-DSA signature value, which is bytes.

  tradSig   The traditional signature value in the appropriate
            encoding for the underlying component algorithm.

Deserialization Process:

  1. Parse each constituent encoded signature.
       The length of the mldsasig is known based on the size of
       the ML-DSA component signature length specified by the Object ID

     switch ML-DSA do
        case ML-DSA-44:
          mldsaSig = bytes[:2420]
          tradSig  = bytes[2420:]
        case ML-DSA-65:
          mldsaSig = bytes[:3309]
          tradSig  = bytes[3309:]
        case ML-DSA-87:
          mldsaSig = bytes[:4627]
          tradSig  = bytes[4627:]

     Note that while ML-DSA has fixed-length signatures, RSA and ECDSA
     may not, depending on encoding, so rigorous length-checking is
     not always possible here.

  2. Output the component signature values

     output (mldsaSig, tradSig)
~~~
{: #alg-composite-deserialize-sig title="DeserializeSignatureValue(bytes) -> (mldsaSig, tradSig)"}


# Use within X.509 and PKIX

The following sections provide processing logic and the necessary ASN.1 modules necessary to use composite ML-DSA within X.509 and PKIX protocols.

While composite ML-DSA keys and signature values MAY be used raw, the following sections provide conventions for using them within X.509 and other PKIX protocols, including defining ASN.1-based wrappers for the binary composite values such that these structures can be used as a drop-in replacement for existing public key and ciphertext fields such as those found in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652].


## Encoding to DER {#sec-encoding-to-der}

The serialization routines presented in {{sec-serialization}} produce raw binary values. When these values are required to be carried within a DER-endeded message format such as an X.509's `subjectPublicKey BIT STRING` and `signatureValue` [RFC5280] or a CMS `SignerInfo.signature OCTET STRING` [RFC5652], then the composite value MUST be wrapped into a DER BIT STRING or OCTET STRING in the obvious ways:

When a BIT STRING is required, the octets of the composite data value SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

When an OCTET STRING is required, the DER encoding of the composite data value SHALL be used directly.



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


## ASN.1 Definitions {#sec-asn1-defs}

The wire encoding of a Composite ML-DSA public key is:

The following ASN.1 Information Object Class is defined to allow for compact definitions of each composite algorithm, leading to a smaller overall ASN.1 module.

~~~ ASN.1
pk-CompositeSignature {OBJECT IDENTIFIER:id, PublicKeyType}
    PUBLIC-KEY ::= {
      IDENTIFIER id
      KEY BIT STRING
      PARAMS ARE absent
      CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyCertSign, cRLSign}
    }
~~~

As an example, the public key type `id-MLDSA44-ECDSA-P256-SHA256` is defined as:

~~~
id-MLDSA44-ECDSA-P256-SHA256 PUBLIC-KEY ::=
  pk-CompositeSignature{
    id-MLDSA44-ECDSA-P256,
    CompositeMLDSAPublicKey }
~~~

The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.


The ASN.1 algorithm object for a composite signature is:

~~~ asn.1
sa-CompositeSignature{OBJECT IDENTIFIER:id,
   PUBLIC-KEY:publicKeyType }
      SIGNATURE-ALGORITHM ::=  {
         IDENTIFIER id
         VALUE BIT STRING
         PARAMS ARE absent
         PUBLIC-KEYS {publicKeyType}
      }
~~~


Use cases that require an interoperable encoding for composite private keys will often need to place a composite private key inside a `OneAsymmetricKey` structure defined in [RFC5958], such as when private keys are carried in PKCS #12 [RFC7292], CMP [RFC4210] or CRMF [RFC4211]. The definition of `OneAsymmetricKey` is copied here for convenience:

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


When a composite private key is conveyed inside a `OneAsymmetricKey` structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the privateKeyAlgorithm field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}} and its parameters field MUST be absent.  The `privateKey` field SHALL contain the OCTET STRING reperesentation of the serialized composite private key as per {{sec-serialize-privkey}}. The `publicKey` field remains OPTIONAL. If the `publicKey` field is present, it MUST be a composite public key as per {{sec-serialize-pubkey}}.

Some applications may need to reconstruct the `OneAsymmetricKey` objects corresponding to each component private key. {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction.

Component keys of a composite MUST NOT be used in any other type of key or as a standalone key.  For more details on the security considerations around key reuse, see section {{sec-cons-key-reuse}}.


# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the list of Composite ML-DSA algorithms and lists the OID and the two component algorithms. Domain separator values are defined below in {{sec-domsep-values}}.

EDNOTE: these are prototyping OIDs to be replaced by IANA.

&lt;CompSig&gt; is equal to 2.16.840.1.114027.80.8.1

## Composite-ML-DSA Algorithm Identifiers

Composite-ML-DSA Signature public key types:

| Composite Signature Algorithm | OID | First Algorithm | Second Algorithm | Pre-Hash |
| ----------- | ----------- | ----------- |  ----------- | ----------- |
| id-MLDSA44-RSA2048-PSS-SHA256           | &lt;CompSig&gt;.100   | id-ML-DSA-44 | id-RSASSA-PSS with id-sha256           | id-sha256 |
| id-MLDSA44-RSA2048-PKCS15-SHA256        | &lt;CompSig&gt;.101   | id-ML-DSA-44 | sha256WithRSAEncryption                | id-sha256 |
| id-MLDSA44-Ed25519-SHA512               | &lt;CompSig&gt;.102   | id-ML-DSA-44 | id-Ed25519                             | id-sha512 |
| id-MLDSA44-ECDSA-P256-SHA256            | &lt;CompSig&gt;.103   | id-ML-DSA-44 | ecdsa-with-SHA256 with secp256r1       | id-sha256 |
| id-MLDSA65-RSA3072-PSS-SHA512           | &lt;CompSig&gt;.104   | id-ML-DSA-65 | id-RSASSA-PSS with id-sha256           | id-sha512 |
| id-MLDSA65-RSA3072-PKCS15-SHA512        | &lt;CompSig&gt;.105   | id-ML-DSA-65 | sha256WithRSAEncryption                | id-sha512 |
| id-MLDSA65-RSA4096-PSS-SHA512           | &lt;CompSig&gt;.106   | id-ML-DSA-65 | id-RSASSA-PSS with id-sha384           | id-sha512 |
| id-MLDSA65-RSA4096-PKCS15-SHA512        | &lt;CompSig&gt;.107   | id-ML-DSA-65 | sha384WithRSAEncryption                | id-sha512 |
| id-MLDSA65-ECDSA-P256-SHA512            | &lt;CompSig&gt;.108   | id-ML-DSA-65 | ecdsa-with-SHA256 with secp256r1       | id-sha512 |
| id-MLDSA65-ECDSA-P384-SHA512            | &lt;CompSig&gt;.109   | id-ML-DSA-65 | ecdsa-with-SHA384 with secp384r1       | id-sha512 |
| id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 | &lt;CompSig&gt;.110   | id-ML-DSA-65 | ecdsa-with-SHA256 with brainpoolP256r1 | id-sha512 |
| id-MLDSA65-Ed25519-SHA512               | &lt;CompSig&gt;.111   | id-ML-DSA-65 | id-Ed25519                             | id-sha512 |
| id-MLDSA87-ECDSA-P384-SHA512            | &lt;CompSig&gt;.112   | id-ML-DSA-87 | ecdsa-with-SHA384 with secp384r1       | id-sha512 |
| id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 | &lt;CompSig&gt;.113   | id-ML-DSA-87 | ecdsa-with-SHA384 with brainpoolP384r1 | id-sha512 |
| id-MLDSA87-Ed448-SHAKE256               | &lt;CompSig&gt;.114   | id-ML-DSA-87 | id-Ed448                               | id-shake256/64 |
| id-MLDSA87-RSA4096-PSS-SHA512           | &lt;CompSig&gt;.115   | id-ML-DSA-87 | id-RSASSA-PSS with id-sha384           | id-sha512 |
| id-MLDSA87-ECDSA-P521-SHA512            | &lt;CompSig&gt;.116   | id-ML-DSA-87 | ecdsa-with-SHA512 with secp521r1       | id-sha512 |
{: #tab-hash-sig-algs title="Hash ML-DSA Composite Signature Algorithms"}

Note that pre-hash functions were chosen to roughly match the security level of the stronger component. In the case of Ed25519 and Ed448 they match the hash function defined in [RFC8032]; SHA512 for Ed25519ph and SHAKE256(x, 64) (that is, 64 bytes of SHAKE256 output) for Ed448

See the ASN.1 module in {{sec-asn1-module}} for the explicit definitions of the above Composite ML-DSA algorithms.

The Pre-Hash algorithm is used as the PH algorithm and the DER Encoded OID value of this Hash is used as HashOID for the Message format in step 2 of `Composite.Sign` in section {{sec-hash-comp-sig-sign}} and `Composite.Verify` in {{sec-hash-comp-sig-verify}}.

As the number of algorithms can be daunting to implementers, see {{sec-impl-profile}} for a discussion of choosing a subset to support.

Full specifications for the referenced algorithms can be found in {{appdx_components}}.


## Domain Separators {#sec-domsep-values}

As mentioned above, the OID input value is used as a domain separator for the Composite Signature Generation and verification process and is the DER encoding of the OID. The following table shows the HEX encoding for each Signature Algorithm.

<!-- Note to authors, this is not auto-generated on build;
     you have to manually re-run the python script and
     commit the results to git.
     This is mainly to save resources and build time on the github commits. -->

{::include src/domSepTable.md}
{: #tab-sig-alg-oids title="Pure ML-DSA Composite Signature Domain Separators"}

## Rationale for choices

In generating the list of Composite algorithms, the following general guidance was used, however during development of this specification several algorithms were added by direct request even though they do not fit this guidance.

* Pair equivalent levels.
* NIST-P-384 is CNSA approved [CNSA2.0] for all classification levels.

SHA2 is used throughout in order to facilitate implementations that do not have easy access to SHA3 outside of the ML-DSA function.

At the higher security levels of pre-hashed Composite ML-DSA, for example `id-MLDSA87-ECDSA-brainpoolP384r1-SHA512`, the 384-bit elliptic curve component is used with SHA2-384 which is its pre-hash (ie the pre-hash that is considered to be internal to the ECDSA component), yet SHA2-512 is used as the pre-hash for the overall composite because in this case the pre-hash must not weaken the ML-DSA-87 component against a collision attack.

## RSASSA-PSS

Use of RSASSA-PSS [RFC8017] requires extra parameters to be specified, which differ for each security level.

Also note that this specification fixes the Public Key OID of RSASSA-PSS to id-RSASSA-PSS (1.2.840.113549.1.1.10), although most implementations also would accept rsaEncryption (1.2.840.113549.1.1.1).

### RSA2048-PSS

The RSA component keys MUST be generated at the 2048-bit security level in order to match that of ML-DSA-44.

As with the other composite signature algorithms, when `id-MLDSA44-RSA2048-PSS` and `id-HashMLDSA44-RSA2048-PSS-SHA256` is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLDSA44-RSA2048-PSS` and `id-HashMLDSA44-RSA2048-PSS-SHA256` SHALL instantiate RSASSA-PSS with the following parameters:

| RSASSA-PSS Parameter       | Value                      |
| -------------------------- | -------------------------- |
| Mask Generation Function   | mgf1 |
| Mask Generation params     | SHA-256           |
| Message Digest Algorithm   | SHA-256           |
| Salt Length in bits        | 256               |
{: #rsa-pss-params2048 title="RSASSA-PSS 2048 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017]
* `SHA-256` is defined in [RFC6234].


### RSA3072-PSS

The RSA component keys MUST be generated at the 3072-bit security level in order to match that of ML-DSA-65.

As with the other composite signature algorithms, when `id-MLDSA65-RSA3072-PSS` or `id-HashMLDSA65-RSA3072-PSS-SHA512`  is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLDSA65-RSA3072-PSS` or `id-HashMLDSA65-RSA3072-PSS-SHA512` SHALL instantiate RSASSA-PSS with the following parameters:

| RSASSA-PSS Parameter       | Value                      |
| -------------------------- | -------------------------- |
| Mask Generation Function   | mgf1 |
| Mask Generation params     | SHA-256                |
| Message Digest Algorithm   | SHA-256                |
| Salt Length in bits        | 256                    |
{: #rsa-pss-params3072 title="RSASSA-PSS 3072 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017]
* `SHA-256` is defined in [RFC6234].

### RSA4096-PSS

The RSA component keys MUST be generated at the 4096-bit security level in order to match that of ML-DSA-65 or ML-DSA-87.

When
* `id-MLDSA65-RSA4096-PSS`,
* `id-HashMLDSA65-RSA4096-PSS-SHA512`,
* `id-MLDSA87-RSA4096-PSS` or
* `id-HashMLDSA87-RSA4096-PSS-SHA512`
is used in an AlgorithmIdentifier, the parameters MUST be absent and RSASSA-PSS SHALL be instantiated with the following parameters:

| RSASSA-PSS Parameter       | Value                      |
| -------------------------- | -------------------------- |
| Mask Generation Function   | mgf1 |
| Mask Generation params     | SHA-384                |
| Message Digest Algorithm   | SHA-384                |
| Salt Length in bits        | 384                    |
{: #rsa-pss-params4096 title="RSASSA-PSS 4096 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017]
* `SHA-384` is defined in [RFC6234].

<!-- End of Composite Signature Algorithm section -->



# ASN.1 Module {#sec-asn1-module}

~~~ asn.1

<CODE STARTS>

{::include Composite-MLDSA-2025.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}
IANA is requested to allocate a value from the "SMI Security for PKIX Module Identifier" registry [RFC7299] for the included ASN.1 module, and allocate values from "SMI Security for PKIX Algorithms" to identify the fourteen Algorithms defined within.

##  Object Identifier Allocations
EDNOTE to IANA: OIDs will need to be replaced in both the ASN.1 module and in {{tab-hash-sig-algs}}.

###  Module Registration - SMI Security for PKIX Module Identifier
-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-Signatures-2025 - id-mod-composite-signatures
-  References: This Document

###  Object Identifier Registrations - SMI Security for PKIX Algorithms

- id-MLDSA44-RSA2048-PSS-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-RSA2048-PSS-SHA256
  - References: This Document

- id-MLDSA44-RSA2048-PKCS15-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-RSA2048-PKCS15-SHA256
  - References: This Document

- id-MLDSA44-Ed25519-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-Ed25519-SHA512
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

- id-MLDSA65-ECDSA-P256-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-ECDSA-P256-SHA512
  - References: This Document

- id-MLDSA65-ECDSA-P384-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-ECDSA-P384-SHA512
  - References: This Document

- id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - References: This Document

- id-MLDSA65-Ed25519-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-Ed25519-SHA512
  - References: This Document

- id-MLDSA87-ECDSA-P384-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-ECDSA-P384-SHA512
  - References: This Document

- id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - References: This Document

- id-MLDSA87-Ed448-SHAKE256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-Ed448-SHAKE256
  - References: This Document

- id-MLDSA87-RSA4096-PSS-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-RSA4096-PSS-SHA512
  - References: This Document

- id-MLDSA87-ECDSA-P521-SHA512
  - Decimal: IANA Assigned
  - Description: id-MLDSA87-ECDSA-P521-SHA512
  - References: This Document


<!-- End of IANA Considerations section -->

# Security Considerations

## Why Hybrids?

In broad terms, a PQ/T Hybrid can be used either to provide dual-algorithm security or to provide migration flexibility. Let's quickly explore both.

Dual-algorithm security. The general idea is that the data is protected by two algorithms such that an attacker would need to break both in order to compromise the data. As with most of cryptography, this property is easy to state in general terms, but becomes more complicated when expressed in formalisms. {{sec-cons-non-separability}} goes into more detail here. One common counter-argument against PQ/T hybrid signatures is that if an attacker can forge one of the component algorithms, then why attack the hybrid-signed message at all when they could simply forge a completely new message? The answer to this question must be found outside the cryptographic primitives themselves, and instead in policy; once an algorithm is known to be broken it ought to be disallowed for single-algorithm use by cryptographic policy, while hybrids involving that algorithm may continue to be used and to provide value.

Migration flexibility. Some PQ/T hybrids exist to provide a sort of "OR" mode where the client can choose to use one algorithm or the other or both. The intention is that the PQ/T hybrid mechanism builds in backwards compatibility to allow legacy and upgraded clients to co-exist and communicate. The Composites presented in this specification do not provide this since they operate in a strict "AND" mode, but they do provide codebase migration flexibility. Consider that an organization has today a mature, validated, certified, hardened implementation of RSA or ECC. Composites allow them to add to this an ML-DSA implementation which immediately starts providing benefits against long-term document integrity attacks even if that ML-DSA implementation is still experimental, non-validated, non-certified, non-hardened implementation. More details of obtaining FIPS certification of a composite algorithm can be found in {{sec-fips}}.


## Non-separability, EUF-CMA and SUF {#sec-cons-non-separability}

The signature combiner defined in this document is Weakly Non-Separable (WNS), as defined in {{I-D.ietf-pquip-hybrid-signature-spectrums}}, since the forged message `M’` will include the composite domain separator as evidence. The prohibition on key reuse between composite and single-algorithm contexts discussed in {{sec-cons-key-reuse}} further strengthens the non-separability in practice, but does not achieve Strong Non-Separability (SNS) since policy mechanisms such as this are outside the definition of SNS.

Unforgeability properties are somewhat more nuanced. We recall first the definitions of Existential Unforgeability under Chosen Message Attack (EUF-CMA) and Strong Unforgeability (SUF).The classic EUF-CMA game is in reference to a pair of algorithms `( Sign(), Verify() )` where the attacker has access to a signing oracle using the `Sign()` and must produce a message-signature pair `(m', s')` that is accepted by the verifier using `Verify()` and where `m` was never signed by the oracle. SUF requires that the attacker cannot construct a new signature to an already-signed message.

The pair `( CompositeML-DSA.Sign(), CompositeML-DSA.Verify() )` is EUF-CMA secure so long as at least one component algorithm is EUF-CMA secure since any attempt to modify the message would cause the EUF-CMA secure component to fail its `Verify()` which in turn will cause `CompositeML-DSA.Verify()` to fail.

CompositeML-DSA only achieves SUF security if both components are SUF secure, which is not a useful property; the argument is that if the first component algorithm is not SUF secure then by definition it admits at least one `(m, s1*)` pair where `s1*` was not produced by the honest signer and it then can be combined with an honestly-signed `(m, s2)` signature over the same message `m` to create `(m, (s1*, s2))` which violates SUF for the composite algorithm. Of the traditional signature component algorithms used in this specification, only Ed25519 and Ed448 are SUF secure and therefore applications that require SUF security to be maintained even in the event that ML-DSA is broken SHOULD use it in composite with Ed25519 or Ed448.

In addition to the classic EUF-CMA game, we should also consider a “cross-protocol” version of the EUF-CMA game that is relevant to hybrids. Specifically, we want to consider a modified version of the EUF-CMA game where the attacker has access to either a signing oracle over the two component algorithms in isolation, `Trad.Sign()` and `ML-DSA.Sign()`, and attempts to fraudulently present them as a composite, or where the attacker has access to a composite oracle for signing and then attempts to split the signature back into components and present them to either `ML-DSA.Verify()` or `Trad.Verify()`.

In the case of CompositeML-DSA, a specific message forgery exists for a cross-protocol EUF-CMA attack, namely introduced by the prefix construction added to M. This applies to use of individual component signing oracles with fraudulent presentation of the signature to a composite verification oracle, and use of a composite signing oracle with fraudulent splitting of the signature for presentation to component verification oracle(s) of either ML-DSA.Verify() or Trad.Verify(). In the first case, an attacker with access to signing oracles for the two component algorithms can sign `M’` and then trivially assemble a composite. In the second case, the message `M’` (containing the composite domain separator) can be presented as having been signed by a standalone component algorithm. However, use of the context string for domain separation enables Weak Non-Separability and auditable checks on hybrid use, which is deemed a reasonable trade-off. Moreover and very importantly, the cross-protocol EUF-CMA attack in either direction is foiled if implementors strictly follow the prohibition on key reuse presented in {{sec-cons-key-reuse}} since there cannot exist simultaneously composite and non-composite signers and verifiers for the same keys.

### Implications of mupliple encodings {#sec-cons-multiple-encodings}

As noted in {{sec-serialization}}, this specification leaves open the choice of encoding of the traditional component. As such it is possible for the same composite public key to carry multiple valid representations `(mldsaPK, tradPK1)` and `(mldsaPK, tradPK2)` where `tradPK1` and `tradPK2` are alternate encodings of the same key, for example compressed vs uncompressed EC points. In theory alternate encodings of the traditional signature value are also possible, although the authors are not aware of any.

In theory this introduces complications for EUF-CMA and SUF-CMA security proofs. Implementors who are concerned with this SHOULD choose implementations of the traditional component that only accept a single encoding and performs appropriate length-checking, and reject composites which contain any other encodings. This is permitted by this specification.


## Key Reuse {#sec-cons-key-reuse}

When using single-algorithm cryptography, the best practice is to always generate fresh key material for each purpose, for example when renewing a certificate, or obtaining both a TLS and S/MIME certificate for the same device, however in practice key reuse in such scenarios is not always catastrophic to security and therefore often tolerated, despite cross-protocol attacks having been shown. (citation needed here)

Within the broader context of PQ / Traditional hybrids, we need to consider new attack surfaces that arise due to the hybrid constructions that did not exist in single-algorithm contexts. One of these is key reuse where the component keys within a hybrid are also used by themselves within a single-algorithm context. For example, it might be tempting for an operator to take an already-deployed RSA key pair and combine it with an ML-DSA key pair to form a hybrid key pair for use in a hybrid algorithm. Within a hybrid signature context this leads to a class of attacks referred to as "stripping attacks" discussed in {{sec-cons-non-separability}} and may also open up risks from further cross-protocol attacks. Despite the weak non-separability property offered by the composite signature combiner, key reuse MUST be avoided to prevent the introduction of EUF-CMA vulnerabilities.

In addition, there is a further implication to key reuse regarding certificate revocation. Upon receiving a new certificate enrolment request, many certification authorities will check if the requested public key has been previously revoked due to key compromise. Often a CA will perform this check by using the public key hash. Therefore, even if both components of a composite have been previously revoked, the CA may only check the hash of the combined composite key and not find the revocations. Therefore, because the possibility of key reuse exists even though forbidden in this specification, CAs performing revocation checks on a composite key SHOULD also check both component keys independently to verify that the component keys have not been revoked.


## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key, certificate, or signature contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), then clients performing signatures or verifications should be updated to adhere to appropriate policies.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled independently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLDSA65-ECDSA-P256-SHA512` even after ECDSA-P256 is deprecated.

When considering stripping attacks, one need consider the case where an attacker has fully compromised one of the component algorithms to the point that they can produce forged signatures that appear valid under one of the component public keys, and thus fool a victim verifier into accepting a forged signature. The protection against this attack relies on the victim verifier trusting the pair of public keys as a single composite key, and not trusting the individual component keys by themselves.

Specifically, in order to achieve this non-separability property, this specification makes two assumptions about how the verifier will establish trust in a composite public key:

1. This specification assumes that all of the component keys within a composite key are freshly generated for the composite; i.e. a given public key MUST NOT appear as a component within a composite key and also within single-algorithm constructions.

2. This specification assumes that composite public keys will be bound in a structure that contains a signature over the public key (for example, an X.509 Certificate [RFC5280]), which is chained back to a trust anchor, and where that signature algorithm is at least as strong as the composite public key that it is protecting.

There are mechanisms within Internet PKI where trusted public keys do not appear within signed structures -- such as the Trust Anchor format defined in [RFC5914]. In such cases, it is the responsibility of implementers to ensure that trusted composite keys are distributed in a way that is tamper-resistant and does not allow the component keys to be trusted independently.

## Use of Prefix to for attack mitigation

The Prefix value specified in the message format calculated in {{sec-sigs}} can be used by a traditional verifier to detect if the composite signature has been stripped apart.  An attacker would need to compute `M' = Prefix || Domain || len(ctx) || ctx || M`  or  `M' :=  Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)`.  Since the Prefix is the constant String "CompositeAlgorithmSignatures2025" (Byte encoding 436F6D706F73697465416C676F726974686D5369676E61747572657332303235 ) a traditional verifier can check if the Message starts with this prefix and reject the message.

<!-- End of Security Considerations section -->

<!-- Start of Appendices -->

--- back

# Approximate Key and Signature Sizes {#sec-sizetable}

Note that the sizes listed below are approximate: these values are measured from the test vectors, but other implementations could produce values where the traditional component has a different size. For example, this could be due to:

* Compressed vs uncompressed EC point.
* The RSA public key `(n, e)` allows `e` to vary is size between 3 and `n - 1` [RFC8017].
* When the underlying RSA or EC value is itself DER-encoded, integer values could occaisionally be shorter than expected due to leading zeros being dropped from the encoding.

Note that by contrast, ML-DSA values are always fixed size, so composite values can always be correctly de-serialized based on the size of the ML-DSA component. It is expected for the size values of RSA and ECDSA variants to fluctuate by a few bytes even between subsequent runs of the same composite implementation signing the same message over different keys. EdDSA values are always fixed size, so the size values for ML-DSA + EdDSA variants can be treated as constants.

Implementations MUST NOT perform strict length checking based on the values in this table.

Non-hybrid ML-DSA is included for reference.

<!-- Note to authors, this is not auto-generated on build;
     you have to manually re-run the python script and
     commit the results to git.
     This is mainly to save resources and build time on the github commits. -->

{::include src/sizeTable.md}
{: #tab-size-values title="Approximate size values of composite ML-DSA"}



# Samples

## Message Format Examples {#appdx-messageFormat-examples}

### Example of MLDSA44-ECDSA-P256-SHA256 with Context

~~~
M' = Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)

M = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }
ctx = new byte[] { 8, 13, 6, 12, 5, 16, 25, 23 }

Encoded Message:
43:6F:6D:70:6F:73:69:74:65:41:6C:67:6F:72:69:74:68:6D:53:69:67:6E:61:74:75:72:65:73:32:30:32:35:06:0B:60:86:48:01:86:FA:6B:50:08:01:53:08:08:0D:06:0C:05:10:19:17:06:09:60:86:48:01:65:03:04:02:01:1F:82:5A:A2:F0:02:0E:F7:CF:91:DF:A3:0D:A4:66:8D:79:1C:5D:48:24:FC:8E:41:35:4B:89:EC:05:79:5A:B3

Prefix: 43:6F:6D:70:6F:73:69:74:65:41:6C:67:6F:72:69:74:68:6D:53:69:67:6E:61:74:75:72:65:73:32:30:32:35:
Domain: :06:0B:60:86:48:01:86:FA:6B:50:08:01:53:
len(ctx): 08:
ctx: 08:0D:06:0C:05:10:19:17:
HashOID: 06:09:60:86:48:01:65:03:04:02:01:
PH(M): 1F:82:5A:A2:F0:02:0E:F7:CF:91:DF:A3:0D:A4:66:8D:79:1C:5D:48:24:FC:8E:41:35:4B:89:EC:05:79:5A:B3
~~~

### Example of MLDSA44-ECDSA-P256-SHA256 without Context

~~~
M' = Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)

M = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }
ctx = not used

Encoded Message:
43:6F:6D:70:6F:73:69:74:65:41:6C:67:6F:72:69:74:68:6D:53:69:67:6E:61:74:75:72:65:73:32:30:32:35:06:0B:60:86:48:01:86:FA:6B:50:08:01:53:00:06:09:60:86:48:01:65:03:04:02:01:1F:82:5A:A2:F0:02:0E:F7:CF:91:DF:A3:0D:A4:66:8D:79:1C:5D:48:24:FC:8E:41:35:4B:89:EC:05:79:5A:B3

Prefix: 43:6F:6D:70:6F:73:69:74:65:41:6C:67:6F:72:69:74:68:6D:53:69:67:6E:61:74:75:72:65:73:32:30:32:35:
Domain: :06:0B:60:86:48:01:86:FA:6B:50:08:01:53
len(ctx): 00:
ctx: empty
HashOID: 06:09:60:86:48:01:65:03:04:02:01:
PH(M): 1F:82:5A:A2:F0:02:0E:F7:CF:91:DF:A3:0D:A4:66:8D:79:1C:5D:48:24:FC:8E:41:35:4B:89:EC:05:79:5A:B3
~~~


# Component Algorithm Reference {#appdx_components}

This section provides references to the full specification of the algorithms used in the composite constructions.

| Component Signature Algorithm ID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-ML-DSA-44 | 2.16.840.1.101.3.4.3.17 | [FIPS.204] |
| id-ML-DSA-65 | 2.16.840.1.101.3.4.3.18 | [FIPS.204] |
| id-ML-DSA-87 | 2.16.840.1.101.3.4.3.19 | [FIPS.204] |
| id-Ed25519   | 1.3.101.112 | [RFC8032], [RFC8410] |
| id-Ed448     | 1.3.101.113 | [RFC8032], [RFC8410] |
| ecdsa-with-SHA256 | 1.2.840.10045.4.3.2 | [RFC5758], [RFC5480], [SEC1], [X9.62–2005] |
| ecdsa-with-SHA384 | 1.2.840.10045.4.3.3 | [RFC5758], [RFC5480], [SEC1], [X9.62–2005] |
| ecdsa-with-SHA512 | 1.2.840.10045.4.3.4 | [RFC5758], [RFC5480], [SEC1], [X9.62–2005] |
| sha256WithRSAEncryption | 1.2.840.113549.1.1.11 | [RFC8017] |
| sha384WithRSAEncryption | 1.2.840.113549.1.1.12 | [RFC8017] |
| id-RSASSA-PSS | 1.2.840.113549.1.1.10 | [RFC8017] |
{: #tab-component-sig-algs title="Component Signature Algorithms used in Composite Constructions"}

| Elliptic CurveID | OID | Specification |
| ----------- | ----------- | ----------- |
| secp256r1 | 1.2.840.10045.3.1.7 | [RFC6090], [SEC2] |
| secp384r1 | 1.3.132.0.34 | [RFC5480], [RFC6090], [SEC2] |
| secp521r1 | 1.3.132.0.35 | [RFC5480], [RFC6090], [SEC2] |
| brainpoolP256r1 | 1.3.36.3.3.2.8.1.1.7 | [RFC5639] |
| brainpoolP384r1 | 1.3.36.3.3.2.8.1.1.11 | [RFC5639] |
{: #tab-component-curve-algs title="Elliptic Curves used in Composite Constructions"}

| HashID | OID | Specification |
| ----------- | ----------- | ----------- |
| id-sha256 | 2.16.840.1.101.3.4.2.1 | [RFC6234] |
| id-sha512 | 2.16.840.1.101.3.4.2.3 | [RFC6234] |
| id-shake256 | 2.16.840.1.101.3.4.2.18 | [FIPS 202] |
{: #tab-component-hash title="Hash algorithms used in pre-hashed Composite Constructions to build PH element"}

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


**RSASSA-PSS 2048 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS   -- (1.2.840.113549.1.1.10)
    }

DER:
  30 0B 06 09 2A 86 48 86 F7 0D 01 01 0A
~~~

**RSASSA-PSS 2048 -- AlgorithmIdentifier of Signature**

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

**RSASSA-PSS 3072 & 4096 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS   -- (1.2.840.113549.1.1.10)
    }

DER:
  30 0B 06 09 2A 86 48 86 F7 0D 01 01 0A
~~~

**RSASSA-PSS 3072 & 4096 -- AlgorithmIdentifier of Signature**

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

**RSASSA-PKCS1-v1_5 2048 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm rsaEncryption,   -- (1.2.840.113549.1.1.1)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
~~~

**RSASSA-PKCS1-v1_5 2048 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signatureAlgorithm AlgorithmIdentifier ::= {
    algorithm sha256WithRSAEncryption,   -- (1.2.840.113549.1.1.11)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 0D 05 00
~~~

**RSASSA-PKCS1-v1_5 3072 & 4096 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm rsaEncryption,   -- (1.2.840.113549.1.1.1)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
~~~

**RSASSA-PKCS1-v1_5 3072 & 4096 -- AlgorithmIdentifier of Signature**

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

**ECDSA NIST-521 -- AlgorithmIdentifier of Public Key**

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ecPublicKey   -- (1.2.840.10045.2.1)
    parameters ANY ::= {
      AlgorithmIdentifier ::= {
        algorithm secp521r1   -- (1.3.132.0.35)
        }
      }
    }

DER:
  30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 23
~~~

**ECDSA NIST-521 -- AlgorithmIdentifier of Signature**

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA512   -- (1.2.840.10045.4.3.4)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 04
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

If backwards compatibility is required, then additional mechanisms will be needed.  Migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to digital signature objects, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], document signing such as in the context of the European eIDAS regulations [eIDAS2014], and publicly trusted code signing [codeSigningBRsv3.8], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] signed structures.  Composite simplifies the protocol design work because it can be implemented as a signature algorithm that fits into existing systems.

### Hybrid Extensions (Keys and Signatures)

The use of Composite Crypto provides the possibility to process multiple algorithms without changing the logic of applications but updating the cryptographic libraries: one-time change across the whole system. However, when it is not possible to upgrade the crypto engines/libraries, it is possible to leverage X.509 extensions to encode the additional keys and signatures. When the custom extensions are not marked critical, although this approach provides the most backward-compatible approach where clients can simply ignore the post-quantum (or extra) keys and signatures, it also requires all applications to be updated for correctly processing multiple algorithms together.



## Profiling down the number of options {#sec-impl-profile}

One immediately daunting aspect of this specification is the number of composite algorithm combinations.
Each option has been specified because there is a community that has a direct application for it; typically because the traditional component is already deployed in a change-managed environment, or because that specific traditional component is required for regulatory reasons.

However, this large number of combinations leads either to fracturing of the ecosystem into non-interoperable sub-groups when different communities choose non-overlapping subsets to support, or on the other hand it leads to spreading development resources too thin when trying to support all options.

This specification does not list any particular composite algorithm as mandatory-to-implement, however organizations that operate within specific application domains are encouraged to define profiles that select a small number of composites appropriate for that application domain.
For applications that do not have any regulatory requirements or legacy implementations to consider, it is RECOMMENDED to focus implemtation effort on:

    id-MLDSA65-ECDSA-P256-SHA512


In applications that require RSA, it is RECOMMENDED to focus implementation effort on:

    id-MLDSA65-RSA3072-PSS-SHA512


In applications that only allow NIST PQC Level 5, it is RECOMMENDED to focus implemtation effort on:

    id-MLDSA87-ECDSA-P384-SHA512

<!-- End of Implementation Considerations section -->


# Test Vectors {#appdx-samples}

The following test vectors are provided in a format similar to the NIST ACVP Known-Answer-Tests (KATs).

The structure is that a global message `m` is signed over in all test cases. `m` is the ASCII string "The quick brown fox jumps over the lazy dog."
Within each test case there are the following values:

* `tcId` the name of the algorithm.
* `pk` the verification public key.
* `x5c` a self-signed X.509 certificate of the public key.
* `sk` the raw signature private key.
* `sk_pkcs8` the signature private key in a PKCS#8 object.
* `s` the signature value.

Implementers should be able to perform the following tests using the test vectors below:

1. Load the public key `pk` or certificate `x5c` and use it to verify the signature `s` over the message `m`.
2. Validate the self-signed certificate `x5c`.
3. Load the signing private key `sk` and use it to produce a new signature which can be verified using the provided `pk` or `x5c`.

Test vectors are provided for each underlying component in isolation for the purposes of debugging.

Due to the length of the test vectors, you may prefer to retrieve them from GitHub. The reference implementation that generated them is also available:

https://github.com/lamps-wg/draft-composite-sigs/tree/main/src

~~~
{::include src/testvectors_wrapped.json}
~~~


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
林邦曄 (Austin Lin, Chunghwa Telecom),
Zhao Peiduo (Seventh Sense AI),
Varun Chatterji (Seventh Sense AI) and
Mojtaba Bisheh-Niasar

We especially want to recognize the contributions of Dr. Britta Hale who has helped immensely with strengthening the signature combiner construction, and with analyzing the scheme with respect to EUF-CMA and Non-Separability properties.

We are grateful to all who have given feedback over the years, formally or informally, on mailing lists or in person, including any contributors who may have been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].

## Making contributions

Additional contributions to this draft are welcome. Please see the working copy of this draft at, as well as open issues at:

https://github.com/lamps-wg/draft-composite-sigs

<!-- End of Contributors section -->
