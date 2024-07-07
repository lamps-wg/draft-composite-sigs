---
title: Composite ML-DSA for use in Internet PKI
abbrev: PQ Composite ML-DSA
docname: draft-ietf-lamps-pq-composite-sigs-latest


# <!-- stand_alone: true -->
ipr: trust200902
area: Security
wg: LAMPS
kw: Internet-Draft
cat: std

coding: us-ascii
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
    street: Kommandantenstr. 15
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


# <!-- EDNOTE: full syntax for this defined here: https://github.com/cabo/kramdown-rfc2629 -->

informative:
  RFC3279:
  RFC7292:
  RFC7296:
  RFC7299:
  RFC8446:
  RFC8551:
  RFC8017:
  I-D.draft-hale-pquip-hybrid-signature-spectrums-01:
  I-D.draft-ounsworth-pq-composite-kem-01:
  I-D.draft-becker-guthrie-noncomposite-hybrid-auth-00:
  I-D.draft-guthrie-ipsecme-ikev2-hybrid-auth-00:
  I-D.draft-pala-klaussner-composite-kofn-00:
  I-D.draft-driscoll-pqt-hybrid-terminology-01:
  I-D.draft-vaira-pquip-pqc-use-cases-00:
  I-D.draft-massimo-lamps-pq-sig-certificates-00:
  I-D.draft-ietf-lamps-dilithium-certificates-01:
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

<!-- This document defines a family of Composite signature schemes that use multiple component cryptographic elements to manage risks associated with the deployment of post-quantum cryptography. Composite schemes are suitable for use within X.509, PKIX and CMS protocols without changes. A set thirteen pairwise combinations are defined to address today's security and regulatory needs that combine ML-DSA with traditional algorithms (e.g., RSA, ECDSA, Ed25519, and Ed448). -->

This document introduces a set of signature schemes designed to leverage pairs of cryptographic elements such as public keys and signatures to combine security properties from two different algorithms. These schemes effectively mitigate risks associated with the adoption of post-quantum cryptography and are fully compatible with existing X.509, PKIX, and CMS protocols, thus requiring no modifications in the number or type of messages. This document defines thirteen specific pairwise combinations that blend ML-DSA with traditional algorithms such as RSA, ECDSA, Ed25519, and Ed448. These combinations are tailored to meet security best practices and regulatory requirements.

<!-- End of Abstract -->


--- middle

# Introduction {#sec-intro}

<!-- During the transition to post-quantum cryptography, there will be uncertainty as to the strength of cryptographic algorithms; we will no longer fully trust traditional cryptography such as RSA, Diffie-Hellman, DSA and their elliptic curve variants, but we will also not fully trust their post-quantum replacements until they have had sufficient scrutiny and time to discover and fix implementation bugs. Unlike previous cryptographic algorithm migrations, the choice of when to migrate and which algorithms to migrate to, is not so clear. Even after the migration period, it may be advantageous for an entity's cryptographic identity to be composed of multiple public-key algorithms.

Cautious implementers may wish to combine cryptographic algorithms such that an attacker would need to break all of them in order to compromise the data being protected. Such mechanisms are referred to as Post-Quantum / Traditional Hybrids {{I-D.driscoll-pqt-hybrid-terminology}}.

In particular, certain jurisdictions are recommending or requiring that PQC lattice schemes only be used within a PQ/T hybrid. As an example, we point to [BSI2021] which includes the following recommendation:

"Therefore, quantum computer-resistant methods should
not be used alone - at least in a transitional period - but
only in hybrid mode, i.e. in combination with a classical
method. For this purpose, protocols must be modified
or supplemented accordingly. In addition, public key
infrastructures, for example, must also be adapted"

This specification represents the straightforward implementation of the hybrid solutions called for by European cyber security agencies.


PQ/T Hybrid cryptography can, in general, provide solutions to two migration problems:

- Algorithm strength uncertainty: During the transition period, some post-quantum signature and encryption algorithms will not be fully trusted, while also the trust in legacy public key algorithms will start to erode.  A relying party may learn some time after deployment that a public key algorithm has become untrustworthy, but in the interim, they may not know which algorithm an adversary has compromised.
- Ease-of-migration: During the transition period, systems will require mechanisms that allow for staged migrations from fully classical to fully post-quantum-aware cryptography.
- Safeguard against faulty algorithm implementations and compromised keys: Even for long known algorithms there is a non-negligible risk of severe implementation faults. Latest examples are the ROCA attack and ECDSA psychic signatures. Using more than one algorithms will mitigate these risks.

This document defines a specific instantiation of the PQ/T Hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single signature such that it can be treated as a single atomic algorithm at the protocol level. Composite algorithms address algorithm strength uncertainty because the composite algorithm remains strong so long as one of its components remains strong. Concrete instantiations of composite signature algorithms are provided based on ML-DSA, RSA and ECDSA. Backwards compatibility is not directly covered in this document, but is the subject of {{sec-backwards-compat}}.

This document is intended for general applicability anywhere that digital signatures are used within PKIX and CMS structures.   For a more detailed use-case discussion for composite signatures, the reader is encouraged to look at {{I-D.vaira-pquip-pqc-use-cases}}

This document attemps to bind the composite component keys together to achieve the weak non-separability property as defined in {{I-D.hale-pquip-hybrid-signature-spectrums}} using a label as defined in {{Bindel2017}}. -->

The advent of quantum computing poses a significant threat to current cryptographic systems. Traditional cryptographic algorithms such as RSA, Diffie-Hellman, DSA, and their elliptic curve variants are vulnerable to quantum attacks. During the transition to post-quantum cryptography (PQC), there is considerable uncertainty regarding the robustness of both existing and new cryptographic algorithms. While we can no longer fully trust traditional cryptography, we also cannot immediately place complete trust in post-quantum replacements until they have undergone extensive scrutiny and real-world testing to uncover and rectify potential implementation flaws.

Unlike previous migrations between cryptographic algorithms, the decision of when to migrate and which algorithms to adopt is far from straightforward. Even after the migration period, it may be advantageous for an entity's cryptographic identity to incorporate multiple public-key algorithms to enhance security.

Cautious implementers may opt to combine cryptographic algorithms in such a way that an attacker would need to break all of them simultaneously to compromise the protected data. These mechanisms are referred to as Post-Quantum/Traditional (PQ/T) Hybrids {{I-D.driscoll-pqt-hybrid-terminology}}.

Certain jurisdictions are already recommending or mandating that PQC lattice schemes be used exclusively within a PQ/T hybrid framework. The use of Composite scheme provides a straightforward implementation of hybrid solutions compatible with (and advocated by) some governments and cybersecurity agencies [BSI2021].

## Conventions and Terminology {#sec-terminology}

<!-- The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}  {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

The following terms are used in this document: -->

{::boilerplate bcp14+}

This document is consistent with the terminology defined in {{-draft-driscoll-pqt-hybrid-terminology}}. In addition, the following terminology is used throughout this document:

ALGORITHM:
          A standardized cryptographic primitive, as well as
          any ASN.1 structures needed for encoding data and
          metadata needed to use the algorithm. This document is
          primarily concerned with algorithms for producing digital
          signatures.

BER:
          Basic Encoding Rules (BER) as defined in [X.690].

CLIENT:
          Any software that is making use of a cryptographic key.
          This includes a signer, verifier, encrypter, decrypter.

COMPONENT ALGORITHM:
          A single basic algorithm which is contained within a
            composite algorithm.

COMPOSITE ALGORITHM:
          An algorithm which is a sequence of two component
            algorithms, as defined in {{sec-composite-structs}}.

DER:
          Distinguished Encoding Rules as defined in [X.690].

LEGACY:   For the purposes of this document, a legacy algorithm is
          any cryptographic algorithm currently in use which is
          not believed to be resistant to quantum cryptanalysis.

PKI:
          Public Key Infrastructure, as defined in [RFC5280].

POST-QUANTUM ALGORITHM:
          Any cryptographic algorithm which is believed to be resistant
          to classical and quantum cryptanalysis, such as the algorithms being considered for standardization by NIST.

PUBLIC / PRIVATE KEY:
          The public and private portion of an asymmetric cryptographic
            key, making no assumptions about which algorithm.

SIGNATURE:
          A digital cryptographic signature, making no assumptions
            about which algorithm.

STRIPPING ATTACK:
          An attack in which the attacker is able to downgrade the
          cryptographic object to an attacker-chosen subset of
          original set of component algorithms in such a way that
          it is not detectable by the receiver. For example,
          substituting a composite public key or signature for a
          version with fewer components.

## Changes since the -01 version
* Added a "Use in CMS" section
* Removed a Falon reference from the ASN.1 document (which was a typo in reference to Falcon)
* Added SMIME-CAPS into the sa-CompositeSignature definition in the ASN.1 module
* Fixed nits and other typos
* Added PSS parameter Salt Lengths
* Changed the OID concatenation section to Domain Separators for clarity
* Accepted some edits by José Ignacio Escribano

## Changes since adoption by the lamps working group
* Added back in the version 13 changes which were dropped by mistake in the initial -00 adopted version
* Added Scott Fluher as an author due to his valuable contributions and participation in the draft writing process
* Removed the reference to Parallel PKI's in implementation considerations as it isn't adding value to the discussion
* Resolved comments from Kris Kwiatkowski regarding FIPS

# Composite Signature Schemes

<!-- {{I-D.driscoll-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme. -->

The engineering principle behind the definition of Composite schemes is to define a new family of algorithms that combines the use of cryptographic operations from two different ones: ML-DSA one and a traditional one.The complexity of combining security properties from the selected two algorithms is handled at the cryptographic library or cryptographic module, thus no changes are expected at the application or protocol level. Composite schemes are fully compatible with the X.509 model: composite public keys, composite private keys, and ciphertexts can be carried in existing data structures and protocols such as PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652], and the Trust Anchor Format [RFC5914].

<!-- End of Introduction section -->

<!-- ## Composite Signatures {#sec-sigs} -->

## Cryptographic Primitives {#sec-sigs}

Composite schemes are defined as cryptographic primitives that consists of three algorithms:

   *  KeyGen() -> (pk, sk): A probabilistic key generation algorithm,
      which generates a public key pk and a secret key sk.

   *  Sign(sk, Message) -> (signature): A signing algorithm which takes
      as input a secret key sk and a Message, and outputs a signature

   *  Verify(pk, Message, signature) -> true or false: A verification algorithm
      which takes as input a public key, a Message, and a signature and outputs true
      if the signature verifies correctly.  Thus it proves the Message was signed
      with the secret key associated with the public key and verifies the integrity
      of the Message.  If the signature and public key cannot verify the Message,
      it returns false.

A composite signature allows two underlying signature algorithms to be combined into a single cryptographic signature operation and can be used for applications that require signatures.

### Composite Key Generation

To generate a new keypair for Composite schemes, the `KeyGen() -> (pk, sk)` function is used. The KeyGen() function calls the two key generation functions of the component algorithms for the Composite keypair. The generated composite public key structure is described in {{sec-composite-pub-keys}}, while the generated composite secret key structure is defined in {{sec-priv-key}}.

The following process is used to generate composite kepair values.

~~~
KeyGen() -> (pk, sk)
Input:
     sk_1, sk_2         Private keys for each component.

     pk_1, pk_2         Public keys for each component.

     A1, A2             Component signature algorithms.

Output:
     (pk, sk)           The composite keypair.

KeyGen():

  (pk_1, sk_1) <- A1.KeyGen()
  (pk_2, sk_2) <- A2.KeyGen()

  if NOT (pk_1, sk_1) or NOT (pk_2, sk_2):
    // Component key generation failure
    return NULL

  (pk, sk) <- encode[(pk_1, sk_1), (pk_2, sk_2)]
  if NOT (pk, sk):
    // Encoding failure
    return False

  // Success
  return (pk, sk)

~~~
{: #alg-composite-keygen title="Composite KeyGen(pk, sk)"}

The component keys MUST be uniquely generated for each component key of a Composite and MUST NOT be used in any other keys or as a standalone key.

### Composite Sign {#sec-comp-sig-gen}

<!-- Generation of a composite signature involves applying each component algorithm's signature process to the input message according to its specification, and then placing each component signature value into the CompositeSignatureValue structure defined in {{sec-composite-sig-structs}}. -->

In multi-algorithm environments, signatures require additional security properties such as non-separability and key binding to mitigate the possibility for new type of attacks that target the new multi-algorithms model. Composite signatures construct provide additional properties such as non-separability and key-binding. For more information, please refer to {{I-D.hale-pquip-hybrid-signature-spectrums}} and the use of labels as defined in {{Bindel2017}}

To this end, the Composite signature generation starts with the pre-hashing the message to be signed together with key-binding data. After that, the signature process for each component algorithm is invoked and the values are then placed in the CompositeSignatureValue structure defined in {{sec-composite-sig-structs}}.

The following process is used to generate composite signature values.

~~~
Sign (sk, Message) -> (signature)
Input:
     K1, K2             Signing private keys for each component. See note below on
                        composite inputs.

     A1, A2             Component signature algorithms. See note below on
                        composite inputs.

     Message            The Message to be signed, an octet string

     HASH               The Message Digest Algorithm used for pre-hashing.  See section
                        on pre-hashing below.

     OID                The Composite Signature String Algorithm Name converted
                        from ASCII to bytes.  See section on OID concatenation
                        below.

Output:
     signature          The composite signature, a CompositeSignatureValue

Signature Generation Process:

   1. Compute a Hash of the Message

         M' = HASH(Message)

   2. Generate the 2 component signatures independently,
      according to their algorithm specifications.

         S1 := Sign( K1, A1, DER(OID) || M' )
         S2 := Sign( K2, A2, DER(OID) || M' )

   3. Encode each component signature S1 and S2 into a BIT STRING
      according to its algorithm specification.

        signature ::= Sequence { S1, S2 }

   4. Output signature
~~~
{: #alg-composite-sign title="Composite Sign(sk, Message)"}

Note on composite inputs: the method of providing the list of component keys and algorithms is flexible and beyond the scope of this pseudo-code.  When passed to the Composite Sign(sk, Message) API the sk is a CompositePrivateKey. It is possible to construct a CompositePrivateKey from component keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this document so long as it produces the same output as the process sketched above.

Since recursive composite public keys are disallowed, no component signature may itself be a composite; ie the signature generation process MUST fail if one of the private keys K1 or K2 is a composite.

A composite signature MUST produce, and include in the output, a signature value for every component key in the corresponding CompositePublicKey, and they MUST be in the same order; ie in the output, S1 MUST correspond to K1, S2 to K2.


### Composite Verify {#sec-comp-sig-verify}

Verification of a composite signature involves applying each component algorithm's verification process according to its specification.

Compliant applications MUST output "Valid signature" (true) if and only if all component signatures were successfully validated, and "Invalid signature" (false) otherwise.

The following process is used to perform this verification.


~~~
Composite Verify(pk, Message, signature)
Input:
     P1, P2             Public verification keys. See note below on
                        composite inputs.

     Message            Message whose signature is to be verified,
                        an octet string.

     signature          CompositeSignatureValue containing the component
                        signature values (S1 and S2) to be verified.

     A1, A2             Component signature algorithms. See note
                        below on composite inputs.

     HASH               The Message Digest Algorithm for pre-hashing.  See
                        section on pre-hashing the message below.

     OID                The Composite Signature String Algorithm Name converted
                        from ASCII to bytes.  See section on OID concatenation
                        below

Output:
    Validity (bool)    "Valid signature" (true) if the composite
                        signature is valid, "Invalid signature"
                        (false) otherwise.

Signature Verification Procedure::
   1. Check keys, signatures, and algorithms lists for consistency.

      If Error during Desequencing, or the sequences have
      different numbers of elements, or any of the public keys
      P1 or P2 and the algorithm identifiers A1 or A2 are
      composite then output "Invalid signature" and stop.

   2. Compute a Hash of the Message

         M' = HASH(Message)

   3. Check each component signature individually, according to its
       algorithm specification.
       If any fail, then the entire signature validation fails.

       if not verify( P1, DER(OID) || M', S1, A1 ) then
            output "Invalid signature"
       if not verify( P2, DER(OID) || M', S2, A2 ) then
            output "Invalid signature"

       if all succeeded, then
        output "Valid signature"
~~~
{: #alg-composite-verify title="Composite Verify(pk, Message, signature)"}

Note on composite inputs: the method of providing the list of component keys and algorithms is flexible and beyond the scope of this pseudo-code.  When passed to the Composite Verify(pk, Message, signature) API the pk is a CompositePublicKey. It is possible to construct a CompositePublicKey from component keys stored in separate software or hardware keystores. Variations in the process to accommodate particular private key storage mechanisms are considered to be conformant to this document so long as it produces the same output as the process sketched above.

Since recursive composite public keys are disallowed, no component signature may itself be a composite; ie the signature generation process MUST fail if one of the private keys K1 or K2 is a composite.

## Domain Separators {#sec-oid-concat}

As mentioned above, the OID input value is used as a domain separator for the Composite Signature Generation and verification process and is the DER encoding of the OID. The following table shows the HEX encoding for each Signature AlgorithmID.

| Composite Signature AlgorithmID | Domain Separator (in Hex encoding)|
| ----------- | ----------- |
| id-MLDSA44-RSA2048-PSS-SHA256 | 060B6086480186FA6B50080101|
| id-MLDSA44-RSA2048-PKCS15-SHA256 |060B6086480186FA6B50080102|
| id-MLDSA44-Ed25519-SHA512 |060B6086480186FA6B50080103|
| id-MLDSA44-ECDSA-P256-SHA256 |060B6086480186FA6B50080104|
| id-MLDSA44-ECDSA-brainpoolP256r1-SHA256 |060B6086480186FA6B50080105|
| id-MLDSA65-RSA3072-PSS-SHA512 |060B6086480186FA6B50080106|
| id-MLDSA65-RSA3072-PKCS15-SHA512 |060B6086480186FA6B50080107|
| id-MLDSA65-ECDSA-P256-SHA512 |060B6086480186FA6B50080108|
| id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 |060B6086480186FA6B50080109|
| id-MLDSA65-Ed25519-SHA512 |060B6086480186FA6B5008010A|
| id-MLDSA87-ECDSA-P384-SHA512 |060B6086480186FA6B5008010B|
| id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 |060B6086480186FA6B5008010C|
| id-MLDSA87-Ed448-SHA512 |060B6086480186FA6B5008010D|
{: #tab-sig-alg-oids title="Composite Signature Domain Separators"}

## PreHashing the Message {#sec-prehash}
As noted in the composite signature generation process and composite signature verification process, the Message should be pre-hashed into M' with the digest algorithm specified in the composite signature algorithm identifier.  The choice of the digest algorithm was chosen with the following criteria:

1. For composites paired with RSA or ECDSA, the hashing algorithm SHA256 or SHA512 is used as part of the RSA or ECDSA signature algorithm and is therefore also used as the composite prehashing algorithm.

1. For ML-DSA signing a digest of the message is allowed as long as the hash function provides at least y bits of classical security strength against both collision and second preimage attacks.   For MLDSA44 y is 128 bits, for MLDSA65 y is 192 bits and for MLDSA87 y is 256 bits.  Therefore SHA256 is paired with RSA and ECDSA with MLDSA44 and SHA512 is paired with RSA and ECDSA with MLDSA65 and MLDSA87 to match the appropriate security strength.

1. Ed25519 [RFC8032] uses SHA512 internally, therefore SHA512 is used to pre-hash the message when Ed25519 is a component algorithm.

1. Ed448 [RFC8032] uses SHAKE256 internally, but to reduce the set of prehashing algorihtms, SHA512 was selected to pre-hash the message when Ed448 is a component algorithm.

<!-- End of Composite Signature Algorithm section -->



## Algorithm Selection Criteria

The composite algorithm combinations defined in this document were chosen according to the following guidelines:

1. A single RSA combination is provided at a key size of 3072 bits, matched with NIST PQC Level 3 algorithms.
1. Elliptic curve algorithms are provided with combinations on each of the NIST [RFC6090], Brainpool [RFC5639], and Edwards [RFC7748] curves. NIST PQC Levels 1 - 3 algorithms are matched with 256-bit curves, while NIST levels 4 - 5 are matched with 384-bit elliptic curves. This provides a balance between matching classical security levels of post-quantum and traditional algorithms, and also selecting elliptic curves which already have wide adoption.
1. NIST level 1 candidates are provided, matched with 256-bit elliptic curves, intended for constrained use cases.

If other combinations are needed, a separate specification should be submitted to the IETF LAMPS working group.  To ease implementation, these specifications are encouraged to follow the construction pattern of the algorithms specified in this document.

The composite structures defined in this specification allow only for pairs of algorithms. This also does not preclude future specification from extending these structures to define combinations with three or more components.




# Composite Signature Structures {#sec-composite-structs}

In order for signatures to be composed of multiple algorithms, we define encodings consisting of a sequence of signature primitives (aka "component algorithms") such that these structures can be used as a drop-in replacement for existing signature fields such as those found in PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652].


## pk-CompositeSignature

The following ASN.1 Information Object Class is a template to be used in defining all composite Signature public key types.

~~~ ASN.1
pk-CompositeSignature {OBJECT IDENTIFIER:id,
  FirstPublicKeyType,SecondPublicKeyType}
    PUBLIC-KEY ::= {
      IDENTIFIER id
      KEY SEQUENCE {
        firstPublicKey BIT STRING (CONTAINING FirstPublicKeyType),
        secondPublicKey BIT STRING (CONTAINING SecondPublicKeyType)
      }
      PARAMS ARE absent
      CERT-KEY-USAGE { digitalSignature, nonRepudiation, keyCertSign, cRLSign}
    }
~~~
{: artwork-name="CompositeKeyObject-asn.1-structures"}

As an example, the public key type `pk-MLDSA65-ECDSA-P256-SHA256` is defined as:

~~~
pk-MLDSA65-ECDSA-P256-SHA256 PUBLIC-KEY ::=
  pk-CompositeSignature{ id-MLDSA65-ECDSA-P256-SHA256,
  OCTET STRING, ECPoint}
~~~

The full set of key types defined by this specification can be found in the ASN.1 Module in {{sec-asn1-module}}.

## CompositeSignaturePublicKey {#sec-composite-pub-keys}

Composite public key data is represented by the following structure:

~~~ ASN.1
CompositeSignaturePublicKey ::= SEQUENCE SIZE (2) OF BIT STRING
~~~
{: artwork-name="CompositeSignaturePublicKey-asn.1-structures"}

A composite key MUST contain two component public keys. The order of the component keys is determined by the definition of the corresponding algorithm identifier as defined in section {{sec-alg-ids}}.

Some applications may need to reconstruct the `SubjectPublicKeyInfo` objects corresponding to each component public key. {{tab-sig-algs}} in {{sec-alg-ids}} provides the necessary mapping between composite and their component algorithms for doing this reconstruction. This also motivates the design choice of `SEQUENCE OF BIT STRING` instead of `SEQUENCE OF OCTET STRING`; using `BIT STRING` allows for easier transcription between CompositeSignaturePublicKey and SubjectPublicKeyInfo.

When the CompositeSignaturePublicKey must be provided in octet string or bit string format, the data structure is encoded as specified in {{sec-encoding-rules}}.

Component keys of a CompositeSignaturePublicKey MUST NOT be used in any other type of key or as a standalone key.

## CompositeSignaturePrivateKey {#sec-priv-key}

Usecases that require an interoperable encoding for composite private keys, such as when private keys are carried in PKCS #12 [RFC7292], CMP [RFC4210] or CRMF [RFC4211] MUST use the following structure.

~~~ ASN.1
CompositeSignaturePrivateKey ::= SEQUENCE SIZE (2) OF OneAsymmetricKey
~~~
{: artwork-name="CompositeSignaturePrivateKey-asn.1-structures"}

Each element is a `OneAsymmetricKey`` [RFC5958] object for a component private key.

The parameters field MUST be absent.

The order of the component keys is the same as the order defined in {{sec-composite-pub-keys}} for the components of CompositeSignaturePublicKey.

When a `CompositeSignaturePrivateKey` is conveyed inside a OneAsymmetricKey structure (version 1 of which is also known as PrivateKeyInfo) [RFC5958], the privateKeyAlgorithm field SHALL be set to the corresponding composite algorithm identifier defined according to {{sec-alg-ids}}, the privateKey field SHALL contain the CompositeSignaturePrivateKey, and the publicKey field MUST NOT be present. Associated public key material MAY be present in the CompositeSignaturePrivateKey.

In some usecases the private keys that comprise a composite key may not be represented in a single structure or even be contained in a single cryptographic module; for example if one component is within the FIPS boundary of a cryptographic module and the other is not; see {sec-fips} for more discussion. The establishment of correspondence between public keys in a CompositeSignaturePublicKey and private keys not represented in a single composite structure is beyond the scope of this document.

Component keys of a CompositeSignaturePrivateKey MUST NOT be used in any other type of key or as a standalone key.

## Encoding Rules {#sec-encoding-rules}
<!-- EDNOTE 7: Examples of how other specifications specify how a data structure is converted to a bit string can be found in RFC 2313, section 10.1.4, 3279 section 2.3.5, and RFC 4055, section 3.2. -->

Many protocol specifications will require that the composite public key and composite private key data structures be represented by an octet string or bit string.

When an octet string is required, the DER encoding of the composite data structure SHALL be used directly.

~~~ ASN.1
CompositeSignaturePublicKeyOs ::= OCTET STRING (CONTAINING CompositeSignaturePublicKey ENCODED BY der)
~~~

When a bit string is required, the octets of the DER encoded composite data structure SHALL be used as the bits of the bit string, with the most significant bit of the first octet becoming the first bit, and so on, ending with the least significant bit of the last octet becoming the last bit of the bit string.

~~~ ASN.1
CompositeSignaturePublicKeyBs ::= BIT STRING (CONTAINING CompositeSignaturePublicKey ENCODED BY der)
~~~

In the interests of simplicity and avoiding compatibility issues, implementations that parse these structures MAY accept both BER and DER.

## Key Usage Bits

For protocols such as X.509 [RFC5280] that specify key usage along with the public key, then the composite public key associated with a composite signature MUST have a signing-type key usage.
This is because the composite public key can only be used in situations
that are appropriate for both component algorithms, so even if the
classical component key supports both signing and encryption,
the post-quantum algorithms do not.


If the keyUsage extension is present in a Certification Authority (CA) certificate that indicates a composite key, then any combination of the following values MAY be present and any other values MUST NOT be present:


~~~
digitalSignature;
nonRepudiation;
keyCertSign; and
cRLSign.
~~~

If the keyUsage extension is present in an End Entity (EE) certificate that indicates a composite key, then any combination of the following values MAY be present and any other values MUST NOT be present:


~~~
digitalSignature; and
nonRepudiation;
~~~

# Composite Signature Structures

## sa-CompositeSignature {#sec-composite-sig-structs}

The ASN.1 algorithm object for a composite signature is:

~~~ asn.1
sa-CompositeSignature {
  OBJECT IDENTIFIER:id,
    PUBLIC-KEY:publicKeyType }
    SIGNATURE-ALGORITHM ::= {
        IDENTIFIER id
        VALUE CompositeSignatureValue
        PARAMS ARE absent
        PUBLIC-KEYS { publicKeyType }
        SMIME-CAPS { IDENTIFIED BY id }
    }
~~~

The following is an explanation how SIGNATURE-ALGORITHM elements are used
to create Composite Signatures:

| SIGNATURE-ALGORITHM element | Definition |
| ---------                  | ---------- |
| IDENTIFIER                  | The Object ID used to identify the composite Signature Algorithm |
| VALUE                       | The Sequence of BIT STRINGS for each component signature value |
| PARAMS                      | Parameters are absent  |
| PUBLIC-KEYS                 | The composite key required to produce the composite signature |


## CompositeSignatureValue {#sec-compositeSignatureValue}

The output of the composite signature algorithm is the DER encoding of the following structure:

~~~ asn.1
CompositeSignatureValue ::= SEQUENCE SIZE (2) OF BIT STRING
~~~
{: artwork-name="composite-sig-asn.1"}

Where each BIT STRING within the SEQUENCE is a signature value produced by one of the component keys. It MUST contain one signature value produced by each component algorithm, and in the same order as specified in the object identifier.

The choice of `SEQUENCE SIZE (2) OF BIT STRING`, rather than for example a single BIT STRING containing the concatenated signature values, is to gracefully handle variable-length signature values by taking advantage of ASN.1's built-in length fields.


# Algorithm Identifiers {#sec-alg-ids}

This section defines the algorithm identifiers for explicit combinations.  For simplicity and prototyping purposes, the signature algorithm object identifiers specified in this document are the same as the composite key object Identifiers.  A proper implementation should not presume that the object ID of a composite key will be the same as its composite signature algorithm.

This section is not intended to be exhaustive and other authors may define other composite signature algorithms so long as they are compatible with the structures and processes defined in this and companion public and private key documents.

Some use-cases desire the flexibility for clients to use any combination of supported algorithms, while others desire the rigidity of explicitly-specified combinations of algorithms.

The following table summarizes the details for each explicit composite signature algorithms:


The OID referenced are TBD for prototyping only, and the following prefix is used for each:

replace &lt;CompSig&gt; with the String "2.16.840.1.114027.80.8.1"

Therefore &lt;CompSig&gt;.1 is equal to 2.16.840.1.114027.80.8.1.1

Signature public key types:

| Composite Signature AlgorithmID | OID | First Algorithm | Second Algorithm | Pre-Hash |
| ----------- | ----------- | ----------- |  ----------- |
| id-MLDSA44-RSA2048-PSS-SHA256      | &lt;CompSig&gt;.1 | MLDSA44  | SHA256WithRSAPSS| SHA256 |
| id-MLDSA44-RSA2048-PKCS15-SHA256    | &lt;CompSig&gt;.2 | MLDSA44  | SHA256WithRSAEncryption| SHA256 |
| id-MLDSA44-Ed25519-SHA512             | &lt;CompSig&gt;.3 | MLDSA44  | Ed25519| SHA512 |
| id-MLDSA44-ECDSA-P256-SHA256         | &lt;CompSig&gt;.4 | MLDSA44  | SHA256withECDSA | SHA256 |
| id-MLDSA44-ECDSA-brainpoolP256r1-SHA256 | &lt;CompSig&gt;.5 | MLDSA44  | SHA256withECDSA| SHA256 |
| id-MLDSA65-RSA3072-PSS-SHA512           | &lt;CompSig&gt;.6 | MLDSA65 | SHA512WithRSAPSS |SHA512 |
| id-MLDSA65-RSA3072-PKCS15-SHA512        | &lt;CompSig&gt;.7  | MLDSA65 | SHA512WithRSAEncryption |SHA512 |
| id-MLDSA65-ECDSA-P256-SHA512            | &lt;CompSig&gt;.8  | MLDSA65 | SHA512withECDSA |SHA512 |
| id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 | &lt;CompSig&gt;.9  | MLDSA65 | SHA512withECDSA |SHA512 |
| id-MLDSA65-Ed25519-SHA512              | &lt;CompSig&gt;.10  | MLDSA65 | Ed25519 |SHA512 |
| id-MLDSA87-ECDSA-P384-SHA512            | &lt;CompSig&gt;.11  | MLDSA87 | SHA512withECDSA |SHA512|
| id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 | &lt;CompSig&gt;.12 | MLDSA87 | SHA512withECDSA | SHA512 |
| id-MLDSA87-Ed448-SHA512              | &lt;CompSig&gt;.13 | MLDSA87 | Ed448 |SHA512 |
{: #tab-sig-algs title="Composite Signature Algorithms"}

The table above contains everything needed to implement the listed explicit composite algorithms. See the ASN.1 module in section {{sec-asn1-module}} for the explicit definitions of the above Composite signature algorithms.


Full specifications for the referenced algorithms can be found as follows:

* _MLDSA_: {{I-D.ietf-lamps-dilithium-certificates}} and [FIPS.204-ipd]
* _ECDSA_: [RFC5480]
* _Ed25519 / Ed448_: [RFC8410]
* _RSAES-PKCS-v1_5_: [RFC8017]
* _RSASSA-PSS_: [RFC8017]


## Notes on id-MLDSA44-RSA2048-PSS-SHA256

Use of RSA-PSS [RFC8017] deserves a special explanation.

The RSA component keys MUST be generated at the 2048-bit security level in order to match with ML-DSA-44

As with the other composite signature algorithms, when `id-MLDSA44-RSA2048-PSS-SHA256` is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLDSA44-RSA2048-PSS-SHA256` SHALL instantiate RSA-PSS with the following parameters:

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


## Notes on id-MLDSA65-RSA3072-PSS-SHA512

The RSA component keys MUST be generated at the 3072-bit security level in order to match with ML-DSA-65.

As with the other composite signature algorithms, when `id-MLDSA65-RSA3072-PSS-SHA512`  is used in an AlgorithmIdentifier, the parameters MUST be absent. `id-MLDSA65-RSA3072-PSS-SHA512` SHALL instantiate RSA-PSS with the following parameters:

| RSA-PSS Parameter          | Value                      |
| -------------------------- | -------------------------- |
| Mask Generation Function   | mgf1 |
| Mask Generation params     | SHA-512                |
| Message Digest Algorithm   | SHA-512                |
| Salt Length in bits        | 512                    |
{: #rsa-pss-params3072 title="RSA-PSS 3072 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017]
* `SHA-512` is defined in [RFC6234].


<!-- End of Composite Signature Algorithm section -->


# Use in CMS

\[EDNOTE: The convention in LAMPS is to specify algorithms and their CMS conventions in separate documents. Here we have presented them in the same document, but this section has been written so that it can easily be moved to a standalone document.\]

Composite Signature algorithms MAY be employed for one or more recipients in the CMS signed-data content type [RFC5652].

## Underlying Components

When a particular Composite Signature OID is supported in CMS, an implementation SHOULD support the corresponding Secure Hash algorithm identifier in {{tab-cms-shas}} that was used as the pre-hash.

The following table lists the MANDATORY HASH algorithms to preserve security and performance characteristics of each composite algorithm.

| Composite Signature AlgorithmID | Secure Hash |
| ----------- | ----------- |
| id-MLDSA44-RSA2048-PSS-SHA256      | SHA256 |
| id-MLDSA44-RSA2048-PKCS15-SHA256    | SHA256 |
| id-MLDSA44-Ed25519-SHA512             | SHA512 |
| id-MLDSA44-ECDSA-P256-SHA256         | SHA256 |
| id-MLDSA44-ECDSA-brainpoolP256r1-SHA256 | SHA256 |
| id-MLDSA65-RSA3072-PSS-SHA512           | SHA512 |
| id-MLDSA65-RSA3072-PKCS15-SHA512        | SHA512 |
| id-MLDSA65-ECDSA-P256-SHA512            | SHA512 |
| id-MLDSA65-ECDSA-brainpoolP256r1-SHA512 | SHA512 |
| id-MLDSA65-Ed25519-SHA512              | SHA512 |
| id-MLDSA87-ECDSA-P384-SHA512            | SHA512|
| id-MLDSA87-ECDSA-brainpoolP384r1-SHA512 |  SHA512 |
| id-MLDSA87-Ed448-SHA512              | SHA512 |
{: #tab-cms-shas title="Composite Signature SHA Algorithms"}

where:

* SHA2 instantiations are defined in [FIPS180].

## SignedData Conventions

As specified in CMS [RFC5652], the digital signature is produced from the message digest and the signer's private key. The signature is computed over different values depending on whether signed attributes are absent or present.

When signed attributes are absent, the composite signature is computed over the content. When signed attributes are present, a hash is computed over the content using the same hash function that is used in the composite pre-hash, and then a message-digest attribute is constructed to contain the resulting hash value, and then the result of DER encoding the set of signed attributes, which MUST include a content-type attribute and a message-digest attribute, and then the composite signature is computed over the DER-encoded output. In summary:

~~~
IF (signed attributes are absent)
   THEN Composite_Sign(content)
ELSE message-digest attribute = Hash(content);
   Composite_Sign(DER(SignedAttributes))
~~~

When using Composite Signatures, the fields in the SignerInfo are used as follows:

digestAlgorithm:
    The digestAlgorithm contains the one-way hash function used by the CMS signer.

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

Section 2.5.2 of [RFC8551] defines the SMIMECapabilities attribute to announce a partial list of algorithms that an S/MIME implementation can support. When constructing a CMS signed-data content type [RFC5652], a compliant implementation MAY include the SMIMECapabilities attribute that announces support for the RSA-KEM Algorithm.

The SMIMECapability SEQUENCE representing a composite signature Algorithm MUST include the appropriate object identifier as per {{tab-cms-shas}} in the capabilityID field.


# ASN.1 Module {#sec-asn1-module}

~~~ asn.1

<CODE STARTS>

{::include Composite-Signatures-2023.asn}

<CODE ENDS>

~~~


# IANA Considerations {#sec-iana}
IANA is requested to allocate a value from the "SMI Security for PKIX Module Identifier" registry [RFC7299] for the included ASN.1 module, and allocate values from "SMI Security for PKIX Algorithms" to identify the fourteen Algorithms defined within.

##  Object Identifier Allocations
EDNOTE to IANA: OIDs will need to be replaced in both the ASN.1 module and in {{tab-sig-algs}}.

###  Module Registration - SMI Security for PKIX Module Identifier
-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: Composite-Signatures-2023 - id-mod-composite-signatures
-  References: This Document

###  Object Identifier Registrations - SMI Security for PKIX Algorithms

-  id-MLDSA44-RSA2048-PSS-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-RSA2048-PSS-SHA256
  - References: This Document

-  id-MLDSA44-RSA2048-PKCS15-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-RSA2048-PKCS15-SHA256
  - References: This Document

-  id-MLDSA44-Ed25519-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-Ed25519-SHA512
  - References: This Document

-  id-MLDSA44-ECDSA-P256-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-ECDSA-P256-SHA256
  - References: This Document

-  id-MLDSA44-ECDSA-brainpoolP256r1-SHA256
  - Decimal: IANA Assigned
  - Description:  id-MLDSA44-ECDSA-brainpoolP256r1-SHA256
  - References: This Document

-  id-MLDSA65-RSA3072-PSS-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-RSA3072-PSS-SHA512
  - References: This Document

-  id-MLDSA65-RSA3072-PKCS15-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-RSA3072-PKCS15-SHA512
  - References: This Document

-  id-MLDSA65-ECDSA-P256-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-ECDSA-P256-SHA512
  - References: This Document

-  id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-ECDSA-brainpoolP256r1-SHA512
  - References: This Document

-  id-MLDSA65-Ed25519-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA65-Ed25519-SHA512
  - References: This Document

-  id-MLDSA87-ECDSA-P384-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-ECDSA-P384-SHA512
  - References: This Document

-  id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-ECDSA-brainpoolP384r1-SHA512
  - References: This Document

-  id-MLDSA87-Ed448-SHA512
  - Decimal: IANA Assigned
  - Description:  id-MLDSA87-Ed448-SHA512
  - References: This Document

<!-- End of IANA Considerations section -->


# Security Considerations

## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key, certificate, or signature contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), then clients performing signatures or verifications should be updated to adhere to appropriate policies.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled indpendently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLDSA65-ECDSA-P256-SHA512` even after ECDSA-P256 is deprecated.

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

### MLDSA44-ECDSA-P256-SHA256 Public Key

{::include examples/MLDSA44-ECDSA-P256-SHA256.pub}

### MLDSA44-ECDSA-P256 Private Key

{::include examples/MLDSA44-ECDSA-P256-SHA256.pvt}


### MLDSA44-ECDSA-P256 Self-Signed X509 Certificate

{::include examples/MLDSA44-ECDSA-P256-SHA256.crt}

# Implementation Considerations {#sec-imp-considers}

## FIPS certification {#sec-fips}

One of the primary design goals of this specification is for the overall composite algorithm to be able to be considered FIPS-approved even when one of the component algorithms is not.

Implementors seeking FIPS certification of a composite Signature algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorith with zero security, and the overall composite should be considered at least as strong and thus FIPS-approved.

The authors wish to note that this gives composite algorithms great future utility both for future cryptographic migrations as well as bridging across jurisdictions; for example defining composite algorithms which combine FIPS cryptography with cryptography from a different national standards body.


## Backwards Compatibility {#sec-backwards-compat}

The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can interoperate with the upgraded systems of the future.  This draft explicitly does not provide backwards compatibility, only upgraded systems will understand the OIDs defined in this document.

If backwards compatibility is required, then additional mechanisms will be needed.  Migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to digital signature objects, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], document signing such as in the context of the European eIDAS regulations [eIDAS2014], and publicly trusted code signing [codeSigningBRsv2.8], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] signed structures.  Composite simplifies the protocol design work because it can be implemented as a signature algorithm that fits into existing systems.

### Hybrid Extensions (Keys and Signatures)
The use of Composite Crypto provides the possibility to process multiple algorithms without changing the logic of applications, but updating the cryptographic libraries: one-time change across the whole system. However, when it is not possible to upgrade the crypto engines/libraries, it is possible to leverage X.509 extensions to encode the additional keys and signatures. When the custom extensions are not marked critical, although this approach provides the most backward-compatible approach where clients can simply ignore the post-quantum (or extra) keys and signatures, it also requires all applications to be updated for correctly processing multiple algorithms together.


<!-- End of Implementation Considerations section -->



# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/


# Contributors and Acknowledgements
This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past few years in pursuit of this document:

Daniel Van Geest (ISARA),
Britta Hale,
Tim Hollebeek (Digicert),
Panos Kampanakis (Cisco Systems),
Richard Kisley (IBM),
Serge Mister (Entrust),
François Rousseau,
Falko Strenzke,
Felipe Ventura (Entrust),
Alexander Ralien (Siemens) and
José Ignacio Escribano


We are grateful to all, including any contributors who may have been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].

## Making contributions

Additional contributions to this draft are welcome. Please see the working copy of this draft at, as well as open issues at:

https://github.com/lamps-wg/draft-composite-sigs

<!-- End of Contributors section -->
