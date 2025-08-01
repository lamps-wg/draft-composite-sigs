---
title: Composite ML-DSA for use in X.509 Public Key Infrastructure
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
  #RFC2119: -- does not need to be explicit; added by bcp14 boilerplate
  RFC2986:
  RFC3279:
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
  RFC8032:
  #RFC8174: -- does not need to be explicit; added by bcp14 boilerplate
  RFC8410:
  X.690:
      title: "Information technology - ASN.1 encoding Rules: Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER) and Distinguished Encoding Rules (DER)"
      date: November 2015
      author:
        - org: ITU-T
      seriesinfo:
        ISO/IEC: 8825-1:2015
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    date: May 21, 2009
    author:
      - org: "Certicom Research"
    target: https://www.secg.org/sec1-v2.pdf
  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    date: January 27, 2010
    author:
      - org: "Certicom Research"
    target: https://www.secg.org/sec2-v2.pdf
  X9.62–2005:
    title: "Public Key Cryptography for the Financial Services Industry The Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: "November 16, 2005"
    author:
      - org: "American National Standards Institute"
  FIPS.186-5:
    title: "Digital Signature Standard (DSS)"
    date: February 3, 2023
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
  FIPS.202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    date: August 2015
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
  FIPS.204:
    title: "Module-Lattice-Based Digital Signature Standard"
    date: August 13, 2024
    author:
      - org: "National Institute of Standards and Technology (NIST)"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
    seriesinfo:
      "FIPS PUB": "204"


informative:
  RFC5914:
  RFC7292:
  RFC7296:
  RFC7299:
  RFC8017:
  RFC8411:
  RFC8446:
  RFC8551:
  RFC9180:
  I-D.draft-ietf-lamps-dilithium-certificates-11:
  I-D.draft-ietf-pquip-hybrid-signature-spectrums-06:
  I-D.draft-ietf-pquip-pqt-hybrid-terminology-06:
  Bindel2017: # Not referenced, but I think it's important to included.
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
  eIDAS2014:
    title: "Regulation (EU) No 910/2014 of the European Parliament and of the Council of 23 July 2014 on electronic identification and trust services for electronic transactions in the internal market and repealing Directive 1999/93/EC"
    author:
     - org: European Parliament and Council
    target: https://eur-lex.europa.eu/eli/reg/2014/910/oj/eng
  codesigningbrsv3.8:
    title: "Baseline Requirements for the Issuance and Management of Publicly‐Trusted Code Signing Certificates Version 3.8.0"
    author:
     - org: CA/Browser Forum
    target: https://cabforum.org/working-groups/code-signing/documents/
  BonehShoup:
    title: "A Graduate Course in Applied Cryptography v0.6"
    author:
      - ins: D. Boneh
        name: Dan Boneh
      - ins: V. Shoup
        name: Victor Shoup
    target: https://crypto.stanford.edu/~dabo/cryptobook/BonehShoup_0_6.pdf
    date: Jan. 2023


--- abstract

This document defines combinations of ML-DSA [FIPS.204] in hybrid with traditional algorithms RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, Ed25519, and Ed448. These combinations are tailored to meet security best practices and regulatory guidelines. Composite ML-DSA is applicable in any application that uses X.509 or PKIX data structures that accept ML-DSA, but where the operator wants extra protection against breaks or catastrophic bugs in ML-DSA.

<!-- End of Abstract -->


--- middle

# Changes in -08

Interop-affecting changes:

* Aligned the hash function used for the RSA component to the RSA key size (Thanks Dan!)

Editorial changes:

* .

# Introduction {#sec-intro}

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic signature algorithms such as RSA, DSA and its elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify both algorithmic weaknesses as well as implementation flaws across all the new implementations.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward.
For instance, the aggressive migration timelines may require deploying PQC algorithms before their implementations have been fully hardened or certified, and dual-algorithm data protection may be desirable over a longer time period to hedge against CVEs and other implementation flaws in the new implementations.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of a composite scheme provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies [BSI2021], [ANSSI2024].

This specification defines a specific instantiation of the PQ/T Hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single signature algorithm presenting a single public key and signature value such that it can be treated as a single atomic algorithm at the protocol level; a property referred to as "protocol backwards compatibility" since it can be applied to protocols that are not explicitly hybrid-aware. Composite algorithms address algorithm strength uncertainty because the composite algorithm remains strong so long as one of its components remains strong. Concrete instantiations of composite ML-DSA algorithms are provided based on ML-DSA, RSASSA-PKCS1-v1_5, RSASSA-PSS, ECDSA, Ed25519, and Ed448. Backwards compatibility in the sense of upgraded systems continuing to inter-operate with legacy systems is not directly covered in this specification, but is the subject of {{sec-backwards-compat}}.

Composite ML-DSA is applicable in any PKIX-related application that would otherwise use ML-DSA.

## Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14+}

This specification is consistent with the terminology defined in {{I-D.ietf-pquip-pqt-hybrid-terminology}}. In addition, the following terminology is used throughout this specification:

**ALGORITHM**:
          The usage of the term "algorithm" within this
          specification generally refers to any function which
          has a registered Object Identifier (OID) for
          use within an ASN.1 AlgorithmIdentifier. This
          loosely, but not precisely, aligns with the
          definitions of "cryptographic algorithm" and
          "cryptographic scheme" given in {{I-D.ietf-pquip-pqt-hybrid-terminology}}.

**COMPONENT / PRIMITIVE**:
  The words "component" or "primitive" are used interchangeably
  to refer to a cryptographic algorithm that is used internally
  within a composite algorithm. For example this could be an
  asymmetric algorithm such as "ML-DSA-65" or "RSASSA-PSS", or a Hash such
  as "SHA256".

**DER**:
          Distinguished Encoding Rules as defined in [X.690].

**PKI**:
          Public Key Infrastructure, as defined in [RFC5280].

**SIGNATURE**:
          A digital cryptographic signature, making no assumptions
            about which algorithm.


Notation:
The algorithm descriptions use python-like syntax. The following symbols deserve special mention:

 * `||` represents concatenation of two byte arrays.

 * `[:]` represents byte array slicing.

 * `(a, b)` represents a pair of values `a` and `b`. Typically this indicates that a function returns multiple values; the exact conveyance mechanism -- tuple, struct, output parameters, etc. -- is left to the implementer.

 * `(a, _)`: represents a pair of values where one -- the second one in this case -- is ignored.

 * `Func<TYPE>()`: represents a function that is parametrized by `<TYPE>` meaning that the function's implementation will have minor differences depending on the underlying TYPE. Typically this means that a function will need to look up different constants or use different underlying cryptographic primitives depending on which composite algorithm it is implementing.


## Composite Design Philosophy

{{I-D.ietf-pquip-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite algorithms, as defined in this specification, follow this definition and should be regarded as a single key that performs a single cryptographic operation typical of a digital signature algorithm, such as key generation, signing, or verifying -- using its internal sequence of component keys as if they form a single key. This generally means that the complexity of combining algorithms can and should be handled by the cryptographic library or cryptographic module, and the single composite public key, private key, and signature value can be carried in existing fields in protocols such as PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], the CMS [RFC5652], and the Trust Anchor Format [RFC5914]. In this way, composites achieve "protocol backwards-compatibility" in that they will drop cleanly into any protocol that accepts an analogous single-algorithm cryptographic scheme without requiring any modification of the protocol to handle multiple algorithms.

Discussion of the specific choices of algorithm pairings can be found in {{sec-rationale}}.


# Overview of the Composite ML-DSA Signature Scheme {#sec-sig-scheme}

Composite ML-DSA is a Post-Quantum / Traditional hybrid signature scheme which combines ML-DSA as specified in [FIPS.204] and {{I-D.ietf-lamps-dilithium-certificates}} with one of RSASSA-PKCS1-v1_5 or RSASSA-PSS algorithms defined in [RFC8017], the Elliptic Curve Digital Signature Algorithm ECDSA scheme defined in section 6 of [FIPS.186-5], or Ed25519 / Ed448 defined in [RFC8410]. The two component signatures are combined into a composite algorithm via a "signature combiner" function which performs randomized pre-hashing and prepends several domain separator values to the message prior to passing it to the component algorithms. Composite ML-DSA achieves weak non-separability as well as several other security properties which are described in the Security Considerations in {{sec-cons}}.

Composite signature schemes are defined as cryptographic primitives that consist of three algorithms:

   * `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm
      which generates a public key `pk` and a secret key `sk`. Some cryptographic modules may also expose a `KeyGen(seed) -> (pk, sk)`, which generates `pk` and `sk` deterministically from a seed. This specification assumes a seed-based keygen for ML-DSA.

   * `Sign(sk, M) -> s`: A signing algorithm which takes
      as input a secret key `sk` and a message `M`, and outputs a signature `s`. Signing routines may take additional parameters such as a context string or a hash function to use for pre-hashing the message.

   * `Verify(pk, M, s) -> true or false`: A verification algorithm
      which takes as input a public key `pk`, a message `M` and a signature `s`, and outputs `true` if the signature verifies correctly and `false` or an error otherwise. Verification routines may take additional parameters such as a context string or a hash function to use for pre-hashing the message.

The following algorithms are defined for serializing and deserializing component values. These algorithms are inspired by similar algorithms in {{RFC9180}}.

   * `SerializePublicKey(mlkdsaPK, tradPK) -> bytes`: Produce a byte string encoding of the component public keys.

   * `DeserializePublicKey(bytes) -> (mldsaPK, tradPK)`: Parse a byte string to recover the component public keys.

  * `SerializePrivateKey(mldsaSeed, tradSK) -> bytes`: Produce a byte string encoding of the component private keys. Note that the keygen seed is used as the interoperable private key format for ML-DSA.

   * `DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)`: Parse a byte string to recover the component private keys.

   * `SerializeSignatureValue(r, mldsaSig, tradSig) -> bytes`: Produce a byte string encoding of the component signature values. The randomizer `r` is explained in {{sec-prehash}}.

   * `DeserializeSignatureValue(bytes) -> (r, mldsaSig, tradSig)`: Parse a byte string to recover the randomizer and the component signature values.

Full definitions of serialization and deserialization algorithms can be found in {{sec-serialization}}.


## Pre-hashing and Randomizer {#sec-prehash}

In [FIPS.204] NIST defines separate algorithms for pure and pre-hashed modes of ML-DSA, referred to as "ML-DSA" and "HashML-DSA" respectively. This specification defines a single mode which is similar in construction to HashML-DSA with the addition of a pre-hash randomizer inspired by [BonehShoup]. See {{sec-cons-randomizer}} for detailed discussion of the security properties of the randomized pre-hash. This design provides a compromised balance between performance and security. Since pre-hashing is done at the composite level, "pure" ML-DSA is used as the underlying ML-DSA primitive.

The primary design motivation behind pre-hashing is to perform only a single pass over the potentially large input message `M`, compared to passing the full message to both component primitives, and to allow for optimizations in cases such as signing the same message digest with multiple different keys. The actual length of the to-be-signed message `M'` depends on the application context `ctx` provided at runtime but since `ctx` has a maximum length of 255 bytes, `M'` has a fixed maximum length which depends on the output size of the hash function chosen as `PH`, but can be computed per composite algorithm.

This simplification into a single strongly-pre-hashed algorithm avoids the need for duplicate sets of "Composite-ML-DSA" and "Hash-Composite-ML-DSA" algorithms.

See {{sec-cons-randomizer}} for a discussion of security implications of the randomized pre-hash.

See {{impl-cons-external-ph}} for a discussion of externalizing the pre-hashing step.



## Prefix, Domain Separators and CTX {#sec-domsep-and-ctx}

When constructing the to-be-signed message representative `M'`, several domain separator values are pre-pended to the message pre-hash prior to signing.

~~~
M' :=  Prefix || Domain || len(ctx) || ctx || r || PH( M )
~~~

First a fixed prefix string is pre-pended which is the byte encoding of the ASCII string
"CompositeAlgorithmSignatures2025" which in hex is:

     436F6D706F73697465416C676F726974686D5369676E61747572657332303235

Additional discussion of the prefix can be found in {{sec-cons-prefix}}.

Next, the Domain separator defined in {{sec-domsep-values}} which is the DER encoding of the OID of the specific composite algorithm is concatenated with the length of the context in bytes, the context, the randomizer `r`, and finally the hash of the message to be signed. The Domain separator serves to bind the signature to the specific composite algorithm used. The context string allows for applications to bind the signature to some application context. The randomizer is described in detail in {{sec-prehash}}.

Note that there are two different context strings `ctx` at play: the first is the application context that is passed in to `Composite-ML-DSA.Sign` and bound to the to-be-signed message `M'`. The second is the `ctx` that is passed down into the underlying `ML-DSA.Sign` and here Composite ML-DSA itself is the application that we wish to bind and so the DER-encoded OID of the composite algorithm, called Domain, is used as the `ctx` for the underlying ML-DSA primitive.


# Composite ML-DSA Functions {#sec-sigs}

This section describes the composite ML-DSA functions needed to instantiate the public API of a digital signature scheme as defined in {{sec-sig-scheme}}.

## Key Generation {#sec-keygen}

In order to maintain security properties of the composite, applications that use composite keys MUST always perform fresh key generations of both component keys and MUST NOT reuse existing key material. See {{sec-cons-key-reuse}} for a discussion.

To generate a new key pair for composite schemes, the `KeyGen() -> (pk, sk)` function is used. The KeyGen() function calls the two key generation functions of the component algorithms independently. Multi-process or multi-threaded applications might choose to execute the key generation functions in parallel for better key generation performance.

The following describes how to instantiate a `KeyGen()` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-DSA<OID>.KeyGen() -> (pk, sk)

Explicit inputs:

  None

Implicit inputs mapped from <OID>:

  ML-DSA     The underlying ML-DSA algorithm and
             parameter set, for example, could be "ML-DSA-65".

  Trad       The underlying traditional algorithm and
             parameter set, for example "RSASSA-PSS"
             or "Ed25519".

Output:

  (pk, sk)   The composite key pair.


Key Generation Process:

  1. Generate component keys

     mldsaSeed = Random(32)
     (mldsaPK, _) = ML-DSA.KeyGen(mldsaSeed)
     (tradPK, tradSK) = Trad.KeyGen()

  2. Check for component key gen failure

     if NOT (mldsaPK, mldsaSK) or NOT (tradPK, tradSK):
       output "Key generation error"

  3. Output the composite public and private keys

     pk = SerializePublicKey(mldsaPK, tradPK)
     sk = SerializePrivateKey(mldsaSeed, tradSK)
     return (pk, sk)

~~~
{: #alg-composite-keygen title="Composite-ML-DSA<OID>.KeyGen() -> (pk, sk)"}

In order to ensure fresh keys, the key generation functions MUST be executed for both component algorithms. Compliant parties MUST NOT use, import or export component keys that are used in other contexts, combinations, or by themselves as keys for standalone algorithm use. For more details on the security considerations around key reuse, see {{sec-cons-key-reuse}}.

Note that in step 2 above, both component key generation processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

Variations in the keygen process above and signature processes below to accommodate particular private key storage mechanisms or alternate interfaces to the underlying cryptographic modules are considered to be conformant to this specification so long as they produce the same output and error handling.
For example, component private keys stored in separate software or hardware modules where it is not possible to do a joint simultaneous keygen would be considered compliant so long as both keys are freshly generated. It is also possible that the underlying cryptographic module does not expose a `ML-DSA.KeyGen(seed)` that accepts an externally-generated seed, and instead an alternate keygen interface must be used. Note however that cryptographic modules that do not support seed-based ML-DSA key generation will be incapable of importing or exporting composite keys in the standard format since the private key serialization routines defined in {{sec-serialize-privkey}} only support ML-DSA keys as seeds.


## Sign {#sec-hash-comp-sig-sign}

The `Sign()` algorithm of Composite ML-DSA mirrors the construction of `ML-DSA.Sign(sk, M, ctx)` defined in Algorithm 3 Section 5.2 of [FIPS.204].
Composite ML-DSA exposes an API similar to that of ML-DSA, despite the fact that it includes pre-hashing in a similar way to HashML-DSA.
Internally it uses pure ML-DSA as the component algorithm since there is no advantage to pre-hashing twice.

See {{sec-prehash}} for a discussion of the pre-hashed design and randomizer `r`.

See {{sec-domsep-and-ctx}} for a discussion on the domain separator and context values.

See {{impl-cons-external-ph}} for a discussion of externalizing the pre-hashing step.

The following describes how to instantiate a `Sign()` function for a given Composite ML-DSA algorithm represented by `<OID>`.

~~~
Composite-ML-DSA<OID>.Sign(sk, M, ctx) -> s

Explicit inputs:

  sk    Composite private key consisting of signing private keys for
        each component.

  M     The message to be signed, an octet string.

  ctx     The application context string used in the composite
          signature combiner, which defaults to the empty string.

Implicit inputs mapped from <OID>:

  ML-DSA  The underlying ML-DSA algorithm and
          parameter set, for example, could be "ML-DSA-65".

  Trad    The underlying traditional algorithm and
          parameter set, for example "RSASSA-PSS with id-sha256"
          or "Ed25519".

  Prefix  The prefix String which is the byte encoding of the String
          "CompositeAlgorithmSignatures2025" which in hex is
      436F6D706F73697465416C676F726974686D5369676E61747572657332303235

  Domain  Domain separator value for binding the signature to the
          Composite ML-DSA OID. Additionally, the composite Domain
          is passed into the underlying ML-DSA primitive as the ctx.
          Domain values are defined in the "Domain Separator Values"
          section below.

  PH      The hash function to use for pre-hashing.


Output:
  s      The composite signature value.


Signature Generation Process:

  1. If len(ctx) > 255:
      return error

  2. Compute the Message representative M'.
     As in FIPS 204, len(ctx) is encoded as a single unsigned byte.
     Randomize the message representative

        r = Random(32)
        M' :=  Prefix || Domain || len(ctx) || ctx || r
                                            || PH( M )

  3. Separate the private key into component keys
     and re-generate the ML-DSA key from seed.

       (mldsaSeed, tradSK) = DeserializePrivateKey(sk)
       (_, mldsaSK) = ML-DSA.KeyGen(mldsaSeed)

  4. Generate the two component signatures independently by calculating
     the signature over M' according to their algorithm specifications.

       mldsaSig = ML-DSA.Sign( mldsaSK, M', ctx=Domain )
       tradSig = Trad.Sign( tradSK, M' )

  5. If either ML-DSA.Sign() or Trad.Sign() return an error, then this
     process MUST return an error.

      if NOT mldsaSig or NOT tradSig:
        output "Signature generation error"

  6. Output the encoded composite signature value.

      s = SerializeSignatureValue(r, mldsaSig, tradSig)
      return s
~~~
{: #alg-composite-sign title="Composite-ML-DSA<OID>.Sign(sk, M, ctx) -> s"}

Note that in step 4 above, both component signature processes are invoked, and no indication is given about which one failed. This SHOULD be done in a timing-invariant way to prevent side-channel attackers from learning which component algorithm failed.

It is possible to use component private keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this specification so long as it produces the same output and error handling as the process sketched above.

## Verify {#sec-hash-comp-sig-verify}

The `Verify()` algorithm of Composite ML-DSA mirrors the construction of `ML-DSA.Verify(pk, M, s, ctx)` defined in Algorithm 3 Section 5.3 of [FIPS.204].
Composite ML-DSA exposes an API similar to that of ML-DSA, despite the fact that it includes pre-hashing in a similar way to HashML-DSA.
Internally it uses pure ML-DSA as the component algorithm since there is no advantage to pre-hashing twice.

Compliant applications MUST output "Valid signature" (true) if and only if all component signatures were successfully validated, and "Invalid signature" (false) otherwise.

The following describes how to instantiate a `Verify()` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-DSA<OID>.Verify(pk, M, s, ctx) -> true or false

Explicit inputs:

  pk      Composite public key consisting of verification public
          keys for each component.

  M       Message whose signature is to be verified, an octet
          string.

  s       A composite signature value to be verified.

  ctx     The application context string used in the composite
          signature combiner, which defaults to the empty string.

Implicit inputs mapped from <OID>:

  ML-DSA  The underlying ML-DSA algorithm and
          parameter set, for example, could be "ML-DSA-65".

  Trad    The underlying traditional algorithm and
          parameter set, for example "RSASSA-PSS with id-sha256"
          or "Ed25519".

  Prefix  The prefix String which is the byte encoding of the String
          "CompositeAlgorithmSignatures2025" which in hex is
      436F6D706F73697465416C676F726974686D5369676E61747572657332303235

  Domain  Domain separator value for binding the signature to the
          Composite ML-DSA OID. Additionally, the composite Domain
          is passed into the underlying ML-DSA primitive as the ctx.
          Domain values are defined in the "Domain Separators"
          section below.

  PH      The Message Digest Algorithm for pre-hashing. See
          section on pre-hashing the message below.

Output:

  Validity (bool)   "Valid signature" (true) if the composite
                    signature is valid, "Invalid signature"
                    (false) otherwise.

Signature Verification Process:

  1. If len(ctx) > 255
       return error

  2. Separate the keys and signatures

     (mldsaPK, tradPK)       = DeserializePublicKey(pk)
     (r, mldsaSig, tradSig)  = DeserializeSignatureValue(s)

   If Error during deserialization, or if any of the component
   keys or signature values are not of the correct type or
   length for the given component algorithm then output
   "Invalid signature" and stop.

  3. Compute a Hash of the Message.
     As in FIPS 204, len(ctx) is encoded as a single unsigned byte.

      M' = Prefix || Domain || len(ctx) || ctx || r
                                        || PH( M )

  4. Check each component signature individually, according to its
     algorithm specification.
     If any fail, then the entire signature validation fails.

      if not ML-DSA.Verify( mldsaPK, M', mldsaSig, ctx=Domain ) then
          output "Invalid signature"

      if not Trad.Verify( tradPK, M', tradSig ) then
          output "Invalid signature"

      if all succeeded, then
         output "Valid signature"
~~~
{: #alg-composite-verify title="Composite-ML-DSA<OID>.Verify(pk, M, signature, ctx)"}

Note that in step 4 above, the function fails early if the first component fails to verify. Since no private keys are involved in a signature verification, there are no timing attacks to consider, so this is ok.


# Serialization {#sec-serialization}

This section presents routines for serializing and deserializing composite public keys, private keys, and signature values to bytes via simple concatenation of the underlying encodings of the component algorithms.
The functions defined in this section are considered internal implementation detail and are referenced from within the public API definitions in {{sec-sigs}}.

Deserialization is possible because ML-DSA has fixed-length public keys, private keys (seeds), and signature values as shown in the following table.

| Algorithm | Public key  | Private key | Signature |
| --------- | ----------- | ----------- |  -------- |
| ML-DSA-44 |     1312    |      32     |    2420   |
| ML-DSA-65 |     1952    |      32     |    3309   |
| ML-DSA-87 |     2592    |      32     |    4627   |
{: #tab-mldsa-sizes title="ML-DSA Key and Signature Sizes in bytes"}

For all serialization routines below, when these values are required to be carried in an ASN.1 structure, they are wrapped as described in {{sec-encoding-to-der}}.

While ML-DSA has a single fixed-size representation for each of public key, private key (seed), and signature, the traditional component might allow multiple valid encodings; for example an elliptic curve public key might be validly encoded as either compressed or uncompressed [SEC1], or an RSA private key could be encoded in Chinese Remainder Theorem form [RFC8017]. In order to obtain interoperability, composite algorithms MUST use the following encodings of the underlying components:

* **ML-DSA**: MUST be encoded as specified in [FIPS.204], using a 32-byte seed as the private key.
* **RSA**: MUST be encoded with the `(n,e)` public key representation as specified in A.1.1 of [RFC8017] and the private key representation as specified in A.1.2 of [RFC8017].
* **ECDSA**: public key MUST be encoded as an `ECPoint` as specified in section 2.2 of [RFC5480], with both compressed and uncompressed keys supported. For maximum interoperability, it is RECOMMENDED to use uncompressed points. A signature MUST be DER encoded as an `Ecdsa-Sig-Value` as specified in section 2.2.3 of [RFC3279].
* **EdDSA**: MUST be encoded as per section 3 of [RFC8032].

Even with fixed encodings for the traditional component, there may be slight differences in size of the encoded value due to, for example, encoding rules that drop leading zeroes. See {{sec-sizetable}} for further discussion of encoded size of each composite algorithm.

The deserialization routines described below do not check for well-formedness of the cryptographic material they are recovering. It is assumed that underlying cryptographic primitives will catch malformed values and raise an appropriate error.

## SerializePublicKey and DeserializePublicKey {#sec-serialize-pubkey}

The serialization routine for keys simply concatenates the public keys of the component signature algorithms, as defined below:

~~~
Composite-ML-DSA.SerializePublicKey(mldsaPK, tradPK) -> bytes

Explicit inputs:

  mldsaPK The ML-DSA public key, which is bytes.

  tradPK  The traditional public key in the appropriate
          encoding for the underlying component algorithm.

Implicit inputs:

  None

Output:

  bytes   The encoded composite public key.


Serialization Process:

  1. Combine and output the encoded public key

     output mldsaPK || tradPK
~~~
{: #alg-composite-serialize-pk title="Composite-ML-DSA.SerializePublicKey(mldsaPK, tradPK) -> bytes"}


Deserialization reverses this process. Each component key is deserialized according to their respective specification as shown in {{appdx_components}}.

The following describes how to instantiate a `DeserializePublicKey(bytes)` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-DSA<OID>.DeserializePublicKey(bytes) -> (mldsaPK, tradPK)

Explicit inputs:

  bytes   An encoded composite public key.

Implicit inputs mapped from <OID>:

  ML-DSA   The underlying ML-DSA algorithm and
           parameter set to use, for example, could be "ML-DSA-65".

Output:

  mldsaPK  The ML-DSA public key, which is bytes.

  tradPK   The traditional public key in the appropriate
           encoding for the underlying component algorithm.

Deserialization Process:

  1. Parse each constituent encoded public key.
       The length of the mldsaKey is known based on the size of
       the ML-DSA component key length specified by the Object ID.

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

     Note that while ML-DSA has fixed-length keys, RSA and ECDSA
     may not, depending on encoding, so rigorous length-checking
     of the overall composite key is not always possible.

  2. Output the component public keys

     output (mldsaPK, tradPK)
~~~
{: #alg-composite-deserialize-pk title="Composite-ML-DSA<OID>.DeserializePublicKey(bytes) -> (mldsaPK, tradPK)"}



## SerializePrivateKey and DeserializePrivateKey {#sec-serialize-privkey}

The serialization routine for keys simply concatenates the private keys of the component signature algorithms, as defined below:

~~~
Composite-ML-DSA.SerializePrivateKey(mldsaSeed, tradSK) -> bytes

Explicit inputs:

  mldsaSeed  The ML-DSA private key, which is the bytes of the seed.

  tradSK     The traditional private key in the appropriate
             encoding for the underlying component algorithm.

Implicit inputs:

  None

Output:

  bytes   The encoded composite private key.


Serialization Process:

  1. Combine and output the encoded private key.

     output mldsaSeed || tradSK
~~~
{: #alg-composite-serialize-sk title="Composite-ML-DSA.SerializePrivateKey(mldsaSeed, tradSK) -> bytes"}


Deserialization reverses this process. Each component key is deserialized according to their respective specification as shown in {{appdx_components}}.

The following describes how to instantiate a `DeserializePrivateKey(bytes)` function. Since ML-DSA private keys are 32 bytes for all parameter sets, this function does not need to be parametrized.

~~~
Composite-ML-DSA.DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)

Explicit inputs:

  bytes   An encoded composite private key.

Implicit inputs:

  That an ML-DSA private key is 32 bytes for all parameter sets.

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

     Note that while ML-DSA has fixed-length keys, RSA and ECDSA
     may not, depending on encoding, so rigorous length-checking
     of the overall composite key is not always possible.

  2. Output the component private keys

     output (mldsaSeed, tradSK)
~~~
{: #alg-composite-deserialize-sk title="Composite-ML-DSA.DeserializePrivateKey(bytes) -> (mldsaSeed, tradSK)"}



## SerializeSignatureValue and DeserializeSignatureValue {#sec-serialize-sig}

The serialization routine for the composite signature value simply concatenates the fixed-length ML-DSA signature value with the signature value from the traditional algorithm, as defined below:

~~~
Composite-ML-DSA.SerializeSignatureValue(r, mldsaSig, tradSig) -> bytes

Explicit inputs:

  r         The 32 byte signature randomizer.

  mldsaSig  The ML-DSA signature value, which is bytes.

  tradSig   The traditional signature value in the appropriate
            encoding for the underlying component algorithm.

Implicit inputs:

  None

Output:

  bytes   The encoded composite signature value.

Serialization Process:

  1. Combine and output the encoded composite signature

     output r || mldsaSig || tradSig

~~~
{: #alg-composite-serialize-sig title="Composite-ML-DSA.SerializeSignatureValue(r, mldsaSig, tradSig) -> bytes"}


Deserialization reverses this process, raising an error in the event that the input is malformed.  Each component signature is deserialized according to their respective specification as shown in {{appdx_components}}.

The following describes how to instantiate a `DeserializeSignatureValue(bytes)` function for a given composite algorithm represented by `<OID>`.

~~~
Composite-ML-DSA<OID>.DeserializeSignatureValue(bytes)
                                            -> (r, mldsaSig, tradSig)

Explicit inputs:

  bytes   An encoded composite signature value.

Implicit inputs mapped from <OID>:

  ML-DSA  The underlying ML-DSA algorithm and
          parameter set to use, for example, could be "ML-DSA-65".

Output:

  r         The 32 byte signature randomizer.

  mldsaSig  The ML-DSA signature value, which is bytes.

  tradSig   The traditional signature value in the appropriate
            encoding for the underlying component algorithm.

Deserialization Process:

  1. Parse the randomizer r.

     r = bytes[:32]
     sigs = bytes[32:]  # truncate off the randomizer

  2. Parse each constituent encoded signature.
     The length of the mldsaSig is known based on the size of
     the ML-DSA component signature length specified by the Object ID.

     switch ML-DSA do
        case ML-DSA-44:
          mldsaSig = sigs[:2420]
          tradSig  = sigs[2420:]
        case ML-DSA-65:
          mldsaSig = sigs[:3309]
          tradSig  = sigs[3309:]
        case ML-DSA-87:
          mldsaSig = sigs[:4627]
          tradSig  = sigs[4627:]

     Note that while ML-DSA has fixed-length signatures, RSA and ECDSA
     may not, depending on encoding, so rigorous length-checking is
     not always possible here.

  3. Output the component signature values

     output (r, mldsaSig, tradSig)
~~~
{: #alg-composite-deserialize-sig title="Composite-ML-DSA<OID>.DeserializeSignatureValue(bytes) -> (r, mldsaSig, tradSig)"}


# Use within X.509 and PKIX

The following sections provide processing logic and the ASN.1 modules necessary to use composite ML-DSA within X.509 and PKIX protocols. Use within the Cryptographic Message Syntax (CMS) will be covered in a separate specification.

While composite ML-DSA keys and signature values MAY be used raw, the following sections provide conventions for using them within X.509 and other PKIX protocols such that Composite ML-DSA can be used as a drop-in replacement for existing digital signature algorithms in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], and related protocols.


## Encoding to DER {#sec-encoding-to-der}

The serialization routines presented in {{sec-serialization}} produce raw binary values. When these values are required to be carried within a DER-encoded message format such as an X.509's `subjectPublicKey` and `signatureValue` BIT STRING [RFC5280] or a CMS `SignerInfo.signature OCTET STRING` [RFC5652], then the composite value MUST be wrapped into a DER BIT STRING or OCTET STRING in the obvious ways.

When a BIT STRING is required, the octets of the composite data value SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

When an OCTET STRING is required, the DER encoding of the composite data value SHALL be used directly.



## Key Usage Bits

When any Composite ML-DSA Object Identifier appears within the `SubjectPublicKeyInfo.AlgorithmIdentifier` field of an X.509 certificate [RFC5280], the key usage certificate extension MUST only contain signing-type key usages.

The normal keyUsage rules for signing-type keys from [RFC5280] apply, and are reproduced here for completeness.

For Certification Authority (CA) certificates that carry a Composite ML-DSA public key, any combination of the following values MAY be present and any other values MUST NOT be present:

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
the post-quantum algorithms do not and therefore the overall composite algorithm does not. Implementations MUST NOT use one component of the composite for the purposes of digital signature and the other component for the purposes of encryption or key establishment.


## ASN.1 Definitions {#sec-asn1-defs}

Composite ML-DSA uses a substantially non-ASN.1 based encoding, as specified in {{sec-serialization}}. However, as composite algorithms will be used within ASN.1-based X.509 and PKIX protocols, some conventions for ASN.1 wrapping are necessary.

The following ASN.1 Information Object Classes are defined to allow for compact definitions of each composite algorithm, leading to a smaller overall ASN.1 module.

~~~ ASN.1
pk-CompositeSignature {OBJECT IDENTIFIER:id}
    PUBLIC-KEY ::= {
      IDENTIFIER id
      -- KEY without ASN.1 wrapping --
      PARAMS ARE absent
      CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyCertSign,
                                                             cRLSign}
    }

sa-CompositeSignature{OBJECT IDENTIFIER:id,
   PUBLIC-KEY:publicKeyType }
      SIGNATURE-ALGORITHM ::=  {
         IDENTIFIER id
         -- VALUE without ASN.1 wrapping --
         PARAMS ARE absent
         PUBLIC-KEYS {publicKeyType}
      }
~~~
{: #asn1-info-classes title="ASN.1 Object Information Classes for Composite ML-DSA"}

As an example, the public key and signature algorithm types associated with `id-MLDSA44-ECDSA-P256-SHA256` are defined as:

~~~
pk-MLDSA44-ECDSA-P256-SHA256 PUBLIC-KEY ::=
  pk-CompositeSignature{ id-MLDSA44-ECDSA-P256-SHA256}

sa-MLDSA44-ECDSA-P256-SHA256 SIGNATURE-ALGORITHM ::=
    sa-CompositeSignature{
       id-MLDSA44-ECDSA-P256-SHA256,
       pk-MLDSA44-ECDSA-P256-SHA256 }
~~~

The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.


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
{: artwork-name="RFC5958-OneAsymmetricKey-asn.1-structure" title="OneAsymmetricKey as defined in [RFC5958]"}

When a composite private key is conveyed inside a `OneAsymmetricKey` structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the `privateKeyAlgorithm` field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}} and its parameters field MUST be absent.  The `privateKey` field SHALL contain the OCTET STRING representation of the serialized composite private key as per {{sec-serialize-privkey}}. The `publicKey` field remains OPTIONAL. If the `publicKey` field is present, it MUST be a composite public key as per {{sec-serialize-pubkey}}.

Some applications might need to reconstruct the `SubjectPublicKeyInfo` or `OneAsymmetricKey` objects corresponding to each component key individually, for example if this is required for invoking the underlying primitive. {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction.

Component keys of a composite MUST NOT be used in any other type of key or as a standalone key.  For more details on the security considerations around key reuse, see {{sec-cons-key-reuse}}.


# Algorithm Identifiers {#sec-alg-ids}

This table summarizes the OID and the component algorithms for each Composite ML-DSA algorithm.

EDNOTE: these are prototyping OIDs to be replaced by IANA.

&lt;CompSig&gt; is equal to 2.16.840.1.114027.80.9.1


| Composite Signature Algorithm | OID | ML-DSA | Trad | Pre-Hash |
| ----------- | ----------- | ----------- |  ----------- | ----------- |
| id-MLDSA44-RSA2048-PSS-SHA256           | &lt;CompSig&gt;.0   | ML-DSA-44 | RSASSA-PSS with SHA256                 | SHA256 |
| id-MLDSA44-RSA2048-PKCS15-SHA256        | &lt;CompSig&gt;.1   | ML-DSA-44 | sha256WithRSAEncryption                | SHA256 |
| id-MLDSA44-Ed25519-SHA512               | &lt;CompSig&gt;.2   | ML-DSA-44 | Ed25519                                | SHA512 |
| id-MLDSA44-ECDSA-P256-SHA256            | &lt;CompSig&gt;.3   | ML-DSA-44 | ecdsa-with-SHA256 with secp256r1       | SHA256 |
| id-MLDSA65-RSA3072-PSS-SHA512           | &lt;CompSig&gt;.4   | ML-DSA-65 | RSASSA-PSS with SHA256                 | SHA512 |
| id-MLDSA65-RSA3072-PKCS15-SHA512        | &lt;CompSig&gt;.5   | ML-DSA-65 | sha256WithRSAEncryption                | SHA512 |
| id-MLDSA65-RSA4096-PSS-SHA512           | &lt;CompSig&gt;.6   | ML-DSA-65 | RSASSA-PSS with SHA384                 | SHA512 |
| id-MLDSA65-RSA4096-PKCS15-SHA512        | &lt;CompSig&gt;.7   | ML-DSA-65 | sha384WithRSAEncryption                | SHA512 |
| id-MLDSA65-ECDSA-P256-SHA512            | &lt;CompSig&gt;.8   | ML-DSA-65 | ecdsa-with-SHA256 with secp256r1       | SHA512 |
| id-MLDSA65-ECDSA-P384-SHA512            | &lt;CompSig&gt;.9   | ML-DSA-65 | ecdsa-with-SHA384 with secp384r1       | SHA512 |
| id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 | &lt;CompSig&gt;.10   | ML-DSA-65 | ecdsa-with-SHA256 with brainpoolP256r1 | SHA512 |
| id-MLDSA65-Ed25519-SHA512               | &lt;CompSig&gt;.11   | ML-DSA-65 | Ed25519                                | SHA512 |
| id-MLDSA87-ECDSA-P384-SHA512            | &lt;CompSig&gt;.12   | ML-DSA-87 | ecdsa-with-SHA384 with secp384r1       | SHA512 |
| id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 | &lt;CompSig&gt;.13   | ML-DSA-87 | ecdsa-with-SHA384 with brainpoolP384r1 | SHA512 |
| id-MLDSA87-Ed448-SHAKE256               | &lt;CompSig&gt;.14   | ML-DSA-87 | Ed448                                  | SHAKE256/512* |
| id-MLDSA87-RSA3072-PSS-SHA512           | &lt;CompSig&gt;.15   | ML-DSA-87 | RSASSA-PSS with SHA256                 | SHA512 |
| id-MLDSA87-RSA4096-PSS-SHA512           | &lt;CompSig&gt;.16   | ML-DSA-87 | RSASSA-PSS with SHA384                 | SHA512 |
| id-MLDSA87-ECDSA-P521-SHA512            | &lt;CompSig&gt;.17   | ML-DSA-87 | ecdsa-with-SHA512 with secp521r1       | SHA512 |
{: #tab-hash-sig-algs title="ML-DSA Composite Signature Algorithms"}

*Note: The pre-hash functions were chosen to roughly match the security level of the stronger component. In the case of Ed25519 and Ed448 they match the hash function defined in [RFC8032]; SHA512 for Ed25519ph and SHAKE256(x, 64), which is SHAKE256 producing 64 bytes (512 bits) of output, for Ed448ph.

Full specifications for the referenced algorithms can be found in {{appdx_components}}.

As the number of algorithms can be daunting to implementers, see {{sec-impl-profile}} for a discussion of choosing a subset to support.


## Domain Separator Values {#sec-domsep-values}

Each Composite ML-DSA algorithm has a unique domain separator value which is used in constructing the message representative `M'` in the `Composite-ML-DSA.Sign()` ({{sec-hash-comp-sig-sign}}) and `Composite-ML-DSA.Verify()` ({{sec-hash-comp-sig-verify}}). This helps protect against component signature values being removed from the composite and used out of context.

The domain separator is simply the DER encoding of the OID. The following table shows the HEX-encoded domain separator value for each Composite ML-DSA algorithm.

<!-- Note to authors, this is not auto-generated on build;
     you have to manually re-run the python script and
     commit the results to git.
     This is mainly to save resources and build time on the github commits. -->

{::include src/domSepTable.md}
{: #tab-sig-alg-oids title="ML-DSA Composite Signature Domain Separators"}

EDNOTE: these domain separators are based on the prototyping OIDs assigned on the Entrust arc. We will need to ask for IANA early assignment of these OIDs so that we can re-compute the domain separators over the final OIDs.



## Rationale for choices {#sec-rationale}

In generating the list of composite algorithms, the idea was to provide composite algorithms at various security levels with varying performance characteristics.

The main design consideration in choosing pairings is to prioritize providing pairings of each ML-DSA security level with commonly-deployed traditional algorithms. This supports the design goal of using composites as a stepping stone to efficiently deploy post-quantum on top of existing hardened and certified traditional algorithm implementations. This was prioritized rather than attempting to exactly match the security level of the post-quantum and traditional components -- which in general is difficult to do since there is no academic consensus on how to compare the "bits of security" against classical attackers and "qubits of security" against quantum attackers.

SHA2 is prioritized over SHA3 in order to facilitate implementations that do not have easy access to SHA3 outside of the ML-DSA module. However SHAKE256 is used with Ed448 since this is already the recommended hash functions chosen for ED448ph in [RFC8032].

In some cases, multiple hash functions are used within the same composite algorithm. Consider for example `id-MLDSA65-ECDSA-P256-SHA512` which requires SHA512 as the overall composite pre-hash in order to maintain the security level of ML-DSA-65, but uses SHA256 within the `ecdsa-with-SHA256 with secp256r1` traditional component.
While this increases the implementation burden of needing to carry multiple hash functions for a single composite algorithm, this aligns with the design goal of choosing commonly-implemented traditional algorithms since `ecdsa-with-SHA256 with secp256r1` is far more common than, for example, `ecdsa-with-SHA512 with secp256r1`.


## RSASSA-PSS Parameters

Use of RSASSA-PSS [RFC8017] requires extra parameters to be specified.

As with the other composite signature algorithms, when a composite algorithm OID involving RSA-PSS is used in an AlgorithmIdentifier, the parameters MUST be absent.


When RSA-PSS is used at the 2048-bit or 3072-bit security level, RSASSA-PSS SHALL be instantiated with the following parameters:


| RSASSA-PSS Parameter         | Value                      |
| --------------------------   | -------------------------- |
| MaskGenAlgorithm.algorithm   | id-mgf1           |
| MaskGenAlgorithm.parameters  | id-sha256         |
| Message Digest Algorithm     | id-sha256         |
| Salt Length in bits          | 256               |
{: #rsa-pss-params2048 title="RSASSA-PSS 2048 and 3072 Parameters"}


When RSA-PSS is used at the 4096-bit security level, RSASSA-PSS SHALL be instantiated with the following parameters:

| RSASSA-PSS Parameter        | Value               |
| --------------------------  | ------------------- |
| MaskGenAlgorithm.algorithm  | id-mgf1             |
| MaskGenAlgorithm.parameters | id-sha384           |
| Message Digest Algorithm    | id-sha384           |
| Salt Length in bits         | 384                 |
{: #rsa-pss-params4096 title="RSASSA-PSS 4096 Parameters"}


Full specifications for the referenced algorithms can be found in {{appdx_components}}.

<!-- End of Composite Signature Algorithm section -->



# ASN.1 Module {#sec-asn1-module}

~~~ asn.1

<CODE STARTS>

{::include Composite-MLDSA-2025.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}
IANA is requested to allocate a value from the "SMI Security for PKIX Module Identifier" registry [RFC7299] for the included ASN.1 module, and allocate values from "SMI Security for PKIX Algorithms" to identify the eighteen algorithms defined within.

##  Object Identifier Allocations
EDNOTE to IANA: OIDs will need to be replaced in both the ASN.1 module and in {{tab-hash-sig-algs}}.

###  Module Registration

The following is to be registered in "SMI Security for PKIX Module Identifier":

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-Signatures-2025 - id-mod-composite-signatures
-  References: This Document

###  Object Identifier Registrations

The following are to be registered in "SMI Security for PKIX Algorithms":

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

- id-MLDSA87-RSA3072-PSS-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-RSA3072-PSS-SHA512
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

# Security Considerations {#sec-cons}

## Why Hybrids?

In broad terms, a PQ/T Hybrid can be used either to provide dual-algorithm security or to provide migration flexibility. Let's quickly explore both.

Dual-algorithm security. The general idea is that the data is protected by two algorithms such that an attacker would need to break both in order to compromise the data. As with most of cryptography, this property is easy to state in general terms, but becomes more complicated when expressed in formalisms. {{sec-cons-non-separability}} goes into more detail here. One common counter-argument against PQ/T hybrid signatures is that if an attacker can forge one of the component algorithms, then why attack the hybrid-signed message at all when they could simply forge a completely new message? The answer to this question must be found outside the cryptographic primitives themselves, and instead in policy; once an algorithm is known to be broken it ought to be disallowed for single-algorithm use by cryptographic policy, while hybrids involving that algorithm may continue to be used and to provide value.

Migration flexibility. Some PQ/T hybrids exist to provide a sort of "OR" mode where the application can choose to use one algorithm or the other or both. The intention is that the PQ/T hybrid mechanism builds in backwards compatibility to allow legacy and upgraded applications to co-exist and communicate. The composites presented in this specification do not provide this since they operate in a strict "AND" mode. They do, however, provide codebase migration flexibility. Consider that an organization has today a mature, validated, certified, hardened implementation of RSA or ECC; composites allow them to add an ML-DSA implementation which immediately starts providing benefits against long-term document integrity attacks even if that ML-DSA implementation is still an experimental, non-validated, non-certified, non-hardened implementation. More details of obtaining FIPS certification of a composite algorithm can be found in {{sec-fips}}.


## Non-separability, EUF-CMA and SUF {#sec-cons-non-separability}

The signature combiner defined in this specification is Weakly Non-Separable (WNS), as defined in {{I-D.ietf-pquip-hybrid-signature-spectrums}}, since the forged message `M’` will include the composite domain separator as evidence. The prohibition on key reuse between composite and single-algorithm contexts discussed in {{sec-cons-key-reuse}} further strengthens the non-separability in practice, but does not achieve Strong Non-Separability (SNS) since policy mechanisms such as this are outside the definition of SNS.

Unforgeability properties are somewhat more nuanced. We recall first the definitions of Existential Unforgeability under Chosen Message Attack (EUF-CMA) and Strong Unforgeability (SUF). The classic EUF-CMA game is in reference to a pair of algorithms `( Sign(), Verify() )` where the attacker has access to a signing oracle using the `Sign()` and must produce a message-signature pair `(m', s')` that is accepted by the verifier using `Verify()` and where `m'` was never signed by the oracle. SUF is similar but requires only that `(m', s') != (m, s)` for any honestly-generated `(m, s)`, i.e. that the attacker cannot construct a new signature to an already-signed message.

The pair `( CompositeML-DSA.Sign(), CompositeML-DSA.Verify() )` is EUF-CMA secure so long as at least one component algorithm is EUF-CMA secure since any attempt to modify the message would cause the EUF-CMA secure component to fail its `Verify()` which in turn will cause `CompositeML-DSA.Verify()` to fail.

Composite ML-DSA only achieves SUF security if both components are SUF secure, which is not a useful property; the argument is that if the first component algorithm is not SUF secure then by definition it admits at least one `(m, s1')` pair where `s1'` was not produced by the honest signer, and the attacker can then combine it with an honestly-signed `(m, s2)` signature produced by the second algorithm over the same message `m` to create `(m, (s1', s2))` which violates SUF for the composite algorithm. Of the traditional signature component algorithms used in this specification, only Ed25519 and Ed448 are SUF secure and therefore applications that require SUF security to be maintained even in the event that ML-DSA is broken SHOULD use it in composite with Ed25519 or Ed448.

In addition to the classic EUF-CMA game, we also consider a “cross-protocol” version of the EUF-CMA game that is relevant to hybrids. Specifically, we want to consider a modified version of the EUF-CMA game where the attacker has access to either a signing oracle over the two component algorithms in isolation, `Trad.Sign()` and `ML-DSA.Sign()`, and attempts to fraudulently present them as a composite, or where the attacker has access to a composite signing oracle and then attempts to split the signature back into components and present them to either `ML-DSA.Verify()` or `Trad.Verify()`.

In the case of Composite ML-DSA, a specific message forgery exists for a cross-protocol EUF-CMA attack, namely introduced by the prefix construction used to construct the to-be-signed message representative `M'`. This applies to use of individual component signing oracles with fraudulent presentation of the signature to a composite verification oracle, and use of a composite signing oracle with fraudulent splitting of the signature for presentation to component verification oracle(s) of either `ML-DSA.Verify()` or `Trad.Verify()`. In the first case, an attacker with access to signing oracles for the two component algorithms can sign `M’` and then trivially assemble a composite. In the second case, the message `M’` (containing the composite domain separator) can be presented as having been signed by a standalone component algorithm. However, use of the context string for domain separation enables Weak Non-Separability and auditable checks on hybrid use, which is deemed a reasonable trade-off. Moreover and very importantly, the cross-protocol EUF-CMA attack in either direction is foiled if implementers strictly follow the prohibition on key reuse presented in {{sec-cons-key-reuse}} since there cannot exist simultaneously composite and non-composite signers and verifiers for the same keys.

### Implications of multiple encodings {#sec-cons-multiple-encodings}

As noted in {{sec-serialization}}, this specification leaves some flexibility the choice of encoding of the traditional component. As such it is possible for the same composite public key to carry multiple valid representations `(mldsaPK, tradPK1)` and `(mldsaPK, tradPK2)` where `tradPK1` and `tradPK2` are alternate encodings of the same key, for example compressed vs uncompressed EC points. In theory alternate encodings of the traditional signature value are also possible, although the authors are not aware of any.

In theory this introduces complications for EUF-CMA and SUF-CMA security proofs. Implementers who are concerned with this SHOULD choose implementations of the traditional component that only accept a single encoding and performs appropriate length-checking, and reject composites which contain any other encodings. This would reduce interoperability with other Composite ML-DSA implementations, but it is permitted by this specification.


## Key Reuse {#sec-cons-key-reuse}

While conformance with this specification requires that both components of a composite key MUST be freshly generated, the designers are aware that some implementers may be forced to break this rule due to operational constraints. This section documents the implications of doing so.

When using single-algorithm cryptography, the best practice is to always generate fresh key material for each purpose, for example when renewing a certificate, or obtaining both a TLS and S/MIME certificate for the same device. However, in practice key reuse in such scenarios is not always catastrophic to security and therefore often tolerated. However this reasoning does not hold in the PQ/T hybrid setting.

Within the broader context of PQ/T hybrids, we need to consider new attack surfaces that arise due to the hybrid constructions that did not exist in single-algorithm contexts. One of these is key reuse where the component keys within a hybrid are also used by themselves within a single-algorithm context. For example, it might be tempting for an operator to take an already-deployed RSA key pair and combine it with an ML-DSA key pair to form a hybrid key pair for use in a hybrid algorithm. Within a hybrid signature context this leads to a class of attacks referred to as "stripping attacks" discussed in {{sec-cons-non-separability}} and may also open up risks from further cross-protocol attacks. Despite the weak non-separability property offered by the composite signature combiner, key reuse MUST be avoided to prevent the introduction of EUF-CMA vulnerabilities.

In addition, there is a further implication to key reuse regarding certificate revocation. Upon receiving a new certificate enrolment request, many certification authorities will check if the requested public key has been previously revoked due to key compromise. Often a CA will perform this check by using the public key hash. Therefore, if one, or even both, components of a composite have been previously revoked, the CA may only check the hash of the combined composite key and not find the revocations. Therefore, because the possibility of key reuse exists even though forbidden in this specification, CAs performing revocation checks on a composite key SHOULD also check both component keys independently to verify that the component keys have not been revoked.

Some application might disregard the requirements of this specification to not reuse key material between single-algorithm and composite contexts. While doing so is still a violation of this specification, the weakening of security from doing so can be mitigated by using an appropriate `ctx` value, such as `ctx=Foobar-dual-cert-sig` to indicate that this signature belongs to the Foobar protocol where two certificates were used to create a single composite signature. This specification does not endorse such uses, and per-application security analysis is needed.


## Use of Prefix for attack mitigation {#sec-cons-prefix}

The Prefix value specified in {{sec-domsep-and-ctx}} allows for cautious implementers to wrap their existing Traditional `Verify()` implementations with a guard that looks for messages starting with this string and fail with an error -- i.e. this can act as an extra protection against taking a composite signature and splitting it back into components. However, an implementation that does this will be unable to perform a Traditional signature and verification on a message which happens to start with this string. The designers accepted this trade-off.

## Implications of signature randomizer {#sec-cons-randomizer}

The primary design motivation behind pre-hashing is to perform only a single pass over the potentially large input message `M` and to allow for optimizations in cases such as signing the same message digest with multiple different keys.

Composite ML-DSA introduces a 32-byte randomizer into the signature representative M'.   This is to prevent a class of attacks unique to composites, which we define as a "mixed-key forgery attack": Take two composite keys `(mldsaPK1, tradPK1)` and `(mldsaPK2, tradPK2)` which do not share any key material and have them produce signatures `(r1, mldsaSig1, tradSig1)` and `(r2, mldsaSig2, tradSig2)` respectively over the same message `M`. Consider whether it is possible to construct a forgery by swapping components and presenting `(r, mldsaSig1, tradSig2)` that verifies under a forged public key `(mldsaPK1, tradPK2)`. This forgery attack is blocked by the randomizer `r` so long as `r1 != r2`.

A failure of randomness, for example `r = 0`, or a fixed value of 'r' effectively reduces r to a prefix that doesn't add value, but it is no worse than the security properties that Composite ML-DSA would have had without the randomizer.

Introduction of the randomizer might introduce other beneficial security properties, but these are outside the scope of design consideration.


## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key or certificate contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), the path to deprecating it through policy and removing it from operational environments is, at least is principle, straightforward.

In the composite model this is less obvious since a PQ/T hybrid is expected to still be considered valid after the traditional component is deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms. In general this should be manageable through policy by removing OIDs for the standalone component algorithms while still allowing OIDs for composite algorithms. However, complications may arise when the composite implementation needs to invoke the cryptographic module for a deprecated component algorithm. In particular, this could lead to complex Cryptographic Bills of Materials that show implementations of deprecated algorithms still present and being used.

<!-- End of Security Considerations section -->


# Implementation Considerations {#sec-imp-considers}

## FIPS certification {#sec-fips}

The following sections give guidance to implementers wishing to FIPS-certify a composite implementation.

This guidance is not authoritative and has not been endorsed by NIST.

One of the primary design goals of this specification is for the overall composite algorithm to be able to be considered FIPS-approved even when one of the component algorithms is not.

Implementers seeking FIPS certification of a composite signature algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorithm with zero security, and the overall composite should be considered at least as strong and thus FIPS-approved.

The composite algorithm has been designed to treat the underlying primitives as "black-box implementations" and not impose any additional requirements on them that could require an existing implementation of an underlying primitive to run in a mode different from the one under which it was certified. For example, the `KeyGen` defined in {{sec-keygen}} invokes `ML-DSA.KeyGen(seed)` which might not be available in a cryptographic module running in FIPS-mode, but {{sec-keygen}} is only a suggested implementation and the composite KeyGen MAY be implemented using a different available interface for ML-DSA.KeyGen. Another example is pre-hashing; a pre-hash is inherent to RSA, ECDSA, and ML-DSA (mu), and composite makes no assumptions or requirements about whether component-specific pre-hashing is done locally as part of the composite, or remotely as part of the component primitive.

The signature randomizer `r` requires the composite implementation to have access to a cryptographic random number generator. However, as noted in {{sec-cons-randomizer}}, this provides additional security properties on top of those provided by ML-DSA, RSA, ECDSA, and EdDSA, and failure of randomness does not compromise the Composite ML-DSA algorithm or the underlying primitives. Therefore it should be possible to exclude this RNG invocation from the FIPS boundary if an implementation is not able to guarantee use of a FIPS-approved RNG.

The authors wish to note that composite algorithms provide a design pattern to provide utility in future situations that require care to remain FIPS-compliant, such as future cryptographic migrations as well as bridging across jurisdictions with non-intersecting cryptographic requirements.


## Backwards Compatibility {#sec-backwards-compat}

The term "backwards compatibility" is used here to mean that existing systems as they are deployed today can interoperate with the upgraded systems of the future.  This draft explicitly does not provide backwards compatibility, only upgraded systems will understand the OIDs defined in this specification.

If backwards compatibility is required, then additional mechanisms will be needed.  Migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to digital signature objects, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], document signing such as in the context of the European eIDAS regulations [eIDAS2014], and publicly trusted code signing [codeSigningBRsv3.8], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] signed structures.  Composite simplifies the protocol design work because it can be implemented as a signature algorithm that fits into existing systems.


## Profiling down the number of options {#sec-impl-profile}

One daunting aspect of this specification is the number of composite algorithm combinations.
Each option has been specified because there is a community that has a direct application for it; typically because the traditional component is already deployed in a change-managed environment, or because that specific traditional component is required for regulatory reasons.

However, this large number of combinations leads either to fracturing of the ecosystem into non-interoperable sub-groups when different communities choose non-overlapping subsets to support, or on the other hand it leads to spreading development resources too thin when trying to support all options.

This specification does not list any particular composite algorithm as mandatory-to-implement, however organizations that operate within specific application domains are encouraged to define profiles that select a small number of composites appropriate for that application domain.
For applications that do not have any regulatory requirements or legacy implementations to consider, it is RECOMMENDED to focus implementation effort on:

    id-MLDSA65-ECDSA-P256-SHA512


In applications that require RSA, it is RECOMMENDED to focus implementation effort on:

    id-MLDSA65-RSA3072-PSS-SHA512


In applications that only allow NIST PQC Level 5, it is RECOMMENDED to focus implementation effort on:

    id-MLDSA87-ECDSA-P384-SHA512


## External Pre-hashing {#impl-cons-external-ph}

Implementers MAY externalize the pre-hash computation outside the module that computes `Composite-ML-DSA.Sign()` in an analogous way to how pre-hash signing is used for RSA, ECDSA or HashML-DSA. Such a modification to the `Composite-ML-DSA.Sign()` algorithm is considered compliant to this specification so long as it produces the same output and error conditions.

Below is a suggested implementation for splitting the pre-hashing and signing between two parties.

~~~
Composite-ML-DSA<OID>.Prehash(M) ->  ph

Explicit inputs:

  M       The message to be signed, an octet string.

Implicit inputs mapped from <OID>:

  PH      The hash function to use for pre-hashing.

Output:

   ph     The pre-hash which equals PH ( M )

Process:


1. Compute the Prehash of the message using the Hash function
    defined by PH

   ph = PH ( M )

2. Output ph
~~~
{: #external-pre-hash title="Generation of the external pre-hash"}


~~~
Composite-ML-DSA<OID>.Sign_ph(sk, ph, ctx) -> s

Explicit inputs:

  sk    Composite private key consisting of signing private keys for
        each component.

  ph     The pre-hash digest over the message

 ctx    The Message context string used in the composite signature
        combiner, which defaults to the empty string.


Implicit inputs mapped from <OID>:

  ML-DSA    The underlying ML-DSA algorithm and
            parameter set, for example, could be "ML-DSA-65".

  Trad      The underlying traditional algorithm and
            parameter set, for example "RSASSA-PSS with id-sha256"
            or "Ed25519".

  Prefix    The prefix String which is the byte encoding of the String
            "CompositeAlgorithmSignatures2025" which in hex is
            436F6D706F73697465416C676F726974686D5369676E61747572657332303235

  Domain    Domain separator value for binding the signature to the
            Composite OID. Additionally, the composite Domain is passed into
            the underlying ML-DSA primitive as the ctx.
            Domain values are defined in the "Domain Separators" section below.

Process:

   1.  Identical to Composite-ML-DSA<OID>.Sign (sk, M, ctx) but replace the internally
       generated PH( M ) from step 2 of Composite-ML-DSA<OID>.Sign (sk, M, ctx)
       with ph which is input into this function.
~~~
{: #external-pre-hash-alg title="Suggested implementation of external pre-hashing"}


<!-- End of Implementation Considerations section -->


<!-- Start of Appendices -->

--- back

# Approximate Key and Signature Sizes {#sec-sizetable}

The sizes listed below are approximate: these values are measured from the test vectors, however, several factors could cause fluctuations in the size of the traditional component. For example, this could be due to:

* Compressed vs uncompressed EC point.
* The RSA public key `(n, e)` allows `e` to vary in size between 3 and `n - 1` [RFC8017].
* When the underlying RSA or EC value is itself DER-encoded, integer values could occasionally be shorter than expected due to leading zeros being dropped from the encoding.

By contrast, ML-DSA values are always fixed size, so composite values can always be correctly de-serialized based on the size of the ML-DSA component. It is expected for the size values of RSA and ECDSA variants to fluctuate by a few bytes even between subsequent runs of the same composite implementation.

Implementations MUST NOT perform strict length checking based on the values in this table except for ML-DSA + EdDSA; since these algorithms produce fixed-size outputs, the values in the table below for these variants MAY be treated as constants.

Non-hybrid ML-DSA is included for reference.

<!-- Note to authors, this is not auto-generated on build;
     you have to manually re-run the python script and
     commit the results to git.
     This is mainly to save resources and build time on the github commits. -->

{::include src/sizeTable.md}
{: #tab-size-values title="Approximate size values of composite ML-DSA"}




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
| id-shake256 | 2.16.840.1.101.3.4.2.18 | [FIPS.202] |
| id-mgf1   | 1.2.840.113549.1.1.8 | [RFC8017] |
{: #tab-component-hash title="Hash algorithms used in pre-hashed Composite Constructions to build PH element"}

# Component AlgorithmIdentifiers for Public Keys and Signatures

Many cryptographic libraries are X.509-focused and do not expose interfaces to instantiate a public key from raw bytes, but only from a SubjectPublicKeyInfo structure as you would find in an X.509 certificate, therefore implementing composite in those libraries requires reconstructing the SPKI for each component algorithm. In order to aid implementers and reduce interoperability issues, this section lists out the full public key and signature AlgorithmIdentifiers for each component algorithm.

For newer Algorithms like Ed25519 or ML-DSA the AlgorithmIdentifiers are the same for Public Key and Signature. Older Algorithms have different AlgorithmIdentifiers for keys and signatures and are specified separately here for each component.

**ML-DSA-44**

AlgorithmIdentifier of Public Key and Signature

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ML-DSA-44   -- (2 16 840 1 101 3 4 3 17)
   }

DER:
  30 0B 06 09 60 86 48 01 65 03 04 03 11
~~~


**ML-DSA-65**

AlgorithmIdentifier of Public Key and Signature

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ML-DSA-65   -- (2 16 840 1 101 3 4 3 18)
   }

DER:
  30 0B 06 09 60 86 48 01 65 03 04 03 12
~~~


**ML-DSA-87**

AlgorithmIdentifier of Public Key and Signature

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-ML-DSA-87   -- (2 16 840 1 101 3 4 3 19)
   }

DER:
  30 0B 06 09 60 86 48 01 65 03 04 03 13
~~~


**RSASSA-PSS 2048 & 3072**

AlgorithmIdentifier of Public Key

Note that we suggest here to use id-RSASSA-PSS (1.2.840.113549.1.1.10) as the public key OID for RSA-PSS, although most implementations also would accept rsaEncryption (1.2.840.113549.1.1.1), and some might in fact prefer or require it.

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS   -- (1.2.840.113549.1.1.10)
    }

DER:
  30 0B 06 09 2A 86 48 86 F7 0D 01 01 0A
~~~

AlgorithmIdentifier of Signature

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

**RSASSA-PSS 4096**

EDNOTE: The previous version was inconsistent about whether RSASSA-PSS 4096 should use SHA-384 or SHA-512. The PR uses SHA-384 because it's more consistent with the key size.  If that is kept, the AlgorithmIdentifier below needs to change.

AlgorithmIdentifier of Public Key

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-RSASSA-PSS   -- (1.2.840.113549.1.1.10)
    }

DER:
  30 0B 06 09 2A 86 48 86 F7 0D 01 01 0A
~~~

AlgorithmIdentifier of Signature

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

**RSASSA-PKCS1-v1_5 2048 & 3072**

 AlgorithmIdentifier of Public Key

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm rsaEncryption,   -- (1.2.840.113549.1.1.1)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
~~~

AlgorithmIdentifier of Signature

~~~
ASN.1:
  signatureAlgorithm AlgorithmIdentifier ::= {
    algorithm sha256WithRSAEncryption,   -- (1.2.840.113549.1.1.11)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 0D 05 00
~~~

**RSASSA-PKCS1-v1_5 4096**

EDNOTE: The previous version was inconsistent about whether RSASSA-PSS 4096 should use SHA-384 or SHA-512. The PR uses SHA-384 because it's more consistent with the key size.  If that is kept, the AlgorithmIdentifier below needs to change.

AlgorithmIdentifier of Public Key

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm rsaEncryption,   -- (1.2.840.113549.1.1.1)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
~~~

AlgorithmIdentifier of Signature

~~~
ASN.1:
  signatureAlgorithm AlgorithmIdentifier ::= {
    algorithm sha512WithRSAEncryption,   -- (1.2.840.113549.1.1.13)
    parameters NULL
    }

DER:
  30 0D 06 09 2A 86 48 86 F7 0D 01 01 0D 05 00
~~~

**ECDSA NIST P256**

AlgorithmIdentifier of Public Key

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

AlgorithmIdentifier of Signature

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA256   -- (1.2.840.10045.4.3.2)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 02
~~~

**ECDSA NIST P384**

AlgorithmIdentifier of Public Key

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

AlgorithmIdentifier of Signature

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA384   -- (1.2.840.10045.4.3.3)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 03
~~~

**ECDSA NIST P521**

AlgorithmIdentifier of Public Key

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

AlgorithmIdentifier of Signature

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA512   -- (1.2.840.10045.4.3.4)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 04
~~~

**ECDSA Brainpool-P256**

AlgorithmIdentifier of Public Key

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

AlgorithmIdentifier of Signature

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA256   -- (1.2.840.10045.4.3.2)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 02
~~~

**ECDSA Brainpool-P384**

AlgorithmIdentifier of Public Key

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

AlgorithmIdentifier of Signature

~~~
ASN.1:
  signature AlgorithmIdentifier ::= {
    algorithm ecdsa-with-SHA384   -- (1.2.840.10045.4.3.3)
    }

DER:
  30 0A 06 08 2A 86 48 CE 3D 04 03 03
~~~

**Ed25519**

AlgorithmIdentifier of Public Key and Signature

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-Ed25519   -- (1.3.101.112)
    }

DER:
  30 05 06 03 2B 65 70
~~~

**Ed448**

AlgorithmIdentifier of Public Key and Signature

~~~
ASN.1:
  algorithm AlgorithmIdentifier ::= {
    algorithm id-Ed448   -- (1.3.101.113)
    }

DER:
  30 05 06 03 2B 65 71
~~~

# Message Representative Examples

This section provides examples of constructing the message representative `M'`, showing all intermediate values. This is intended to be useful for debugging purposes.


The input message for this example is the hex string "00 01 02 03 04 05 06 07 08 09".

Each input component is shown. Note that values are shown hex-encoded for display purposes only, they are actually raw binary values.

* `Prefix` is the fixed constant defined in {{sec-domsep-and-ctx}}.
* `Domain` is the specific domain separator for this composite algorithm, as defined in {{sec-domsep-values}}.
* `len(ctx)` is the length of the Message context String which is 00 when no context is used.
* `ctx` is the Message context string used in the composite signature combiner.  It is empty in this example.
* `r` is a random 32-byte value chosen by the signer.
* `PH(r||M)` is the output of hashing the randomizer together with the message `M`.

Finally, the fully assembled `M'` is given, which is simply the concatenation of the above values.

First is an example of constructing the message representative `M'` for MLDSA65-ECDSA-P256-SHA256 without a context string `ctx`.

~~~
{::include ./src/messageFormatSample_noctx.md}
~~~

Second is an example of constructing the message representative `M'` for MLDSA65-ECDSA-P256-SHA256 with a context string `ctx`.

The inputs are similar to the first example with the exception that there is an 8 byte context string 'ctx'.

~~~
{::include ./src/messageFormatSample_ctx.md}
~~~


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
3. Load the signing private key `sk` or `sk_pkcs8` and use it to produce a new signature which can be verified using the provided `pk` or `x5c`.

Test vectors are provided for each underlying ML-DSA algorithm in isolation for the purposes of debugging.

Due to the length of the test vectors, some readers will prefer to retrieve the non-word-wrapped copy from GitHub. The reference implementation written in python that generated them is also available:

https://github.com/lamps-wg/draft-composite-sigs/tree/main/src

TODO: lock this to a specific commit.

~~~
{::include src/testvectors_wrapped.json}
~~~


# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/


# Contributors and Acknowledgements
This document incorporates contributions and comments from a large group of experts. The editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past six years in pursuit of this document:


Serge Mister (Entrust),
Felipe Ventura (Entrust),
Richard Kettlewell (Entrust),
Ali Noman (Entrust),
Daniel Van Geest (CryptoNext),
Dr. Britta Hale (Naval Postgraduade School),
Tim Hollebeek (Digicert),
Panos Kampanakis (Amazon),
Chris A. Wood (Apple),
Christopher D. Wood (Apple),
Sophie Schmieg (Google),
Bas Westerbaan (Cloudflare),
Deirdre Connolly (SandboxAQ),
Richard Kisley (IBM),
Piotr Popis (Enigma),
François Rousseau,
Falko Strenzke,
Alexander Ralien (Siemens),
José Ignacio Escribano,
Jan Oupický,
陳志華 (Abel C. H. Chen, Chunghwa Telecom),
林邦曄 (Austin Lin, Chunghwa Telecom),
Zhao Peiduo (Seventh Sense AI),
Phil Hallin (Microsoft),
Samuel Lee (Microsoft),
Alicja Kario (Red Hat),
Jean-Pierre Fiset (Crypto4A),
Varun Chatterji (Seventh Sense AI),
Mojtaba Bisheh-Niasar and
Douglas Stebila (University of Waterloo).


We especially want to recognize the contributions of Dr. Britta Hale who has helped immensely with strengthening the signature combiner construction, and with analyzing the scheme with respect to EUF-CMA and Non-Separability properties.

Thanks to Giacomo Pope (github.com/GiacomoPope) whose ML-DSA and ML-KEM implementations were used to generate the test vectors.

We are grateful to all who have given feedback over the years, formally or informally, on mailing lists or in person, including any contributors who may have been inadvertently omitted from this list.

Finally, we wish to thank the authors of all the referenced documents upon which this specification was built. "Copying always makes things easier and less error prone" - [RFC8411].


<!-- End of Contributors section -->
