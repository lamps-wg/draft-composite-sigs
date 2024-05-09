---
title: Composite Signatures For Use In Internet PKI
abbrev: PQ Composite Sigs
# <!-- EDNOTE: Edits the draft name -->
docname: draft-ounsworth-pq-composite-sigs-12

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
      org: CableLabs
      email: director@openca.org
      abbrev: CableLabs
      street: 858 Coal Creek Circle
      city: Louisville, Colorado
      country: United States of America
      code: 80027  
      
    -
      ins: J. Klaussner
      name: Jan Klaussner
      org: D-Trust GmbH
      email: jan.klaussner@d-trust.net
      street: Kommandantenstr. 15
      code: 10969
      city: Berlin
      country: Germany
      
  
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


--- abstract

The migration to post-quantum cryptography is unique in the history of modern digital cryptography in that neither the old outgoing nor the new incoming algorithms are fully trusted to protect data for the required data lifetimes. The outgoing algorithms, such as RSA and elliptic curve, may fall to quantum cryptanalysis, while the incoming post-quantum algorithms face uncertainty about both the underlying mathematics as well as hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

Cautious implementers may wish to layer cryptographic algorithms such that an attacker would need to break all of them in order to compromise the data being protected using either a Post-Quantum / Traditional Hybrid, Post-Quantum / Post-Quantum Hybrid, or combinations thereof. This document, and its companions, defines a specific instantiation of hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single key or signature such that they can be treated as a single atomic object at the protocol level.

This document defines the structures CompositeSignaturePublicKey, CompositeSignaturePrivateKey and CompositeSignatureValue, which are sequences of the respective structure for each component algorithm.  Composite signature algorithm identifiers are specified in this document which represent the explicit combinations of the underlying component algorithms. 

<!-- End of Abstract -->


--- middle

# Changes in version -12

* Fixed the ASN.1 module pk-CompositeSignature Information Object Class so it now compiles

# Changes in version -11

* Remove ambiguity and made it clear that all component signature MUST be verified
* Added language to ensure that component keys MUST not be used in any other context
* Changed the content of the OID artifact to the DER encoded OID
* Reduced number of pre-hashing algorithm by removing SHA384 and SHAKE and replacing those with SHA512
* Updated the prototype OIDs since the changes in this draft are not compatible with version -10
* Fixed other nits


# Introduction {#sec-intro}

During the transition to post-quantum cryptography, there will be uncertainty as to the strength of cryptographic algorithms; we will no longer fully trust traditional cryptography such as RSA, Diffie-Hellman, DSA and their elliptic curve variants, but we will also not fully trust their post-quantum replacements until they have had sufficient scrutiny and time to discover and fix implementation bugs. Unlike previous cryptographic algorithm migrations, the choice of when to migrate and which algorithms to migrate to, is not so clear. Even after the migration period, it may be advantageous for an entity's cryptographic identity to be composed of multiple public-key algorithms.

Cautious implementers may wish to combine cryptographic algorithms such that an attacker would need to break all of them in order to compromise the data being protected. Such mechanisms are referred to as Post-Quantum / Traditional Hybrids {{I-D.driscoll-pqt-hybrid-terminology}}.

PQ/T Hybrid cryptography can, in general, provide solutions to two migration problems:

- Algorithm strength uncertainty: During the transition period, some post-quantum signature and encryption algorithms will not be fully trusted, while also the trust in legacy public key algorithms will start to erode.  A relying party may learn some time after deployment that a public key algorithm has become untrustworthy, but in the interim, they may not know which algorithm an adversary has compromised.
- Ease-of-migration: During the transition period, systems will require mechanisms that allow for staged migrations from fully classical to fully post-quantum-aware cryptography.
- Safeguard against faulty algorithm implementations and compromised keys: Even for long known algorithms there is a non-negligible risk of severe implementation faults. Latest examples are the ROCA attack and ECDSA psychic signatures. Using more than one algorithms will mitigate these risks.

This document defines a specific instantiation of the PQ/T Hybrid paradigm called "composite" where multiple cryptographic algorithms are combined to form a single signature such that it can be treated as a single atomic algorithm at the protocol level. Composite algorithms address algorithm strength uncertainty because the composite algorithm remains strong so long as one of its components remains strong. Concrete instantiations of composite signature algorithms are provided based on ML-DSA, Falcon, RSA and ECDSA. Backwards compatibility is not directly covered in this document, but is the subject of {{sec-backwards-compat}}.

This document is intended for general applicability anywhere that digital signatures are used within PKIX and CMS structures.   For a more detailed use-case discussion for composite signatures, the reader is encouraged to look at {{I-D.vaira-pquip-pqc-use-cases}}

## Terminology {#sec-terminology}
The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{RFC2119}}  {{RFC8174}} when, and only when, they appear in all capitals, as shown here.

The following terms are used in this document:

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
          An algorithm which is a sequence of two or more component
            algorithms, as defined in {{sec-composite-structs}}.

DER:
          Distinguished Encoding Rules as defined in [X.690].

LEGACY:   For the purposes of this document, a legacy algorithm is
          any cryptographic algorithm currently is use which is 
          not believe to be resistant to quantum cryptanalysis.

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


## Composite Design Philosophy

{{I-D.driscoll-pqt-hybrid-terminology}} defines composites as:

>   *Composite Cryptographic Element*:  A cryptographic element that
>      incorporates multiple component cryptographic elements of the same
>      type in a multi-algorithm scheme.

Composite keys as defined here follow this definition and should be regarded as a single key that performs a single cryptographic operation such key generation, signing, verifying, encapsulating, or decapsulating -- using its internal sequence of component keys as if they form a single key. This generally means that the complexity of combining algorithms can and should be handled by the cryptographic library or cryptographic module, and the single composite public key, private key, and ciphertext can be carried in existing fields in protocols such as PKCS#10 [RFC2986], CMP [RFC4210], X.509 [RFC5280], CMS [RFC5652], and the Trust Anchor Format [RFC5914]. In this way, composites achieve "protocol backwards-compatibility" in that they will drop cleanly into any protocol that accepts signature algorithms without requiring any modification of the protocol to handle multiple keys.

<!-- End of Introduction section -->

## Composite Signatures {#sec-sigs}

Here we define the signature mechanism in which a signature is a cryptographic primitive that consists of three algorithms:

   *  KeyGen() -> (pk, sk): A probabilistic key generation algorithm,
      which generates a public key pk and a secret key sk.

   *  Sign(sk, Message) -> (signature): A signing algorithm which takes 
      as input a secret key sk and a Message, and outputs a signature

   *  Verify(pk, Message, signature) -> true or false: A verification algorithm
      which takes as input a public key, a Message and signature and outputs true
      if the signature and public key can be used to verify the message.  Thus it
      proves the Message was signed with the secret key associated with the public 
      key and verifies the integrity of the Message.  If the signature and public
      key cannot verify the Message, it returns false.   

A composite signature allows two or more underlying signature algorithms to be combined into a single cryptographic signature operation and can be used for applications that require signatures.  

### Composite KeyGen

The `KeyGen() -> (pk, sk)` of a composite signature algorithm will perform the `KeyGen()` of the respective component signature algorithms and it produces a composite public key `pk` as per {{sec-composite-pub-keys}} and a composite secret key `sk` is per {{sec-priv-key}}.  The component keys MUST be uniquely generated for each component key of a Composite and MUST NOT be used in any other keys or as a standalone key.  


### Composite Sign {#sec-comp-sig-gen}

Generation of a composite signature involves applying each component algorithm's signature process to the input message according to its specification, and then placing each component signature value into the CompositeSignatureValue structure defined in {{sec-composite-sig-structs}}.

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
         
   2. Generate the n component signatures independently,
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
                        an octet string
     
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

## OID Concatenation {#sec-oid-concat}

As mentioned above, the OID input value for the Composite Signature Generation and verification process is the DER encoding of the OID represented in Hexidecimal bytes.   The following table shows the HEX encoding for each Signature AlgorithmID

| Composite Signature AlgorithmID | DER Encoding to be prepended to each Message | 
| ----------- | ----------- | ----------- |  ----------- | 
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
| id-Falon512-ECDSA-P256-SHA256 |060B6086480186FA6B5008010E|
| id-Falcon512-ECDSA-brainpoolP256r1-SHA256 |060B6086480186FA6B5008010F|
| id-Falcon512-Ed25519-SHA512 |060B6086480186FA6B50080110|
{: #tab-sig-alg-oids title="Composite Signature OID Concatenations"}

## PreHashing the Message {#sec-prehash}
As noted in the composite signature generation process and composite signature verification process, the Message should be pre-hashed into M' with the digest algorithm specified in the composite signature algorithm identifier.  The choice of the digest algorithm was chosen with the following criteria:

1. For composites paired with RSA or ECDSA, the hashing algorithm SHA256 or SHA512 is used as part of the RSA or ECDSA signature algorithm and is therefore also used as the composite prehashing algorithm.   

1. For ML-DSA signing a digest of the message is allowed as long as the hash function provides at least y bits of classical security strength against both collision and second preimage attacks.   For MLDSA44 y is 128 bits, MLDSA65 y is 192 bits and for MLDSA87 y is 256 bits.  Therefore SHA256 is paired with RSA and ECDSA with MLDSA44 and SHA512 is paired with RSA and ECDSA with MLDSA65 and MLDSA87 to match the appropriate security strength.

1. Ed25519 [RFC8032] uses SHA512 internally, therefore SHA512 is used to pre-hash the message when Ed25519 is a component algorithm.  

1. Ed448 [RFC8032] uses SHAKE256 internally, but to reduce the set of prehashing algorihtms, SHA512 was selected to pre-hash the message when Ed448 is a component algorithm.
  
1. TODO:  For Falcon signing it is expected prehashing digest accomodations will be allowed.  

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

This section is not intended to be exhaustive and other authors may define others composite signature algorithms so long as they are compatible with the structures and processes defined in this and companion public and private key documents.

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
| id-Falon512-ECDSA-P256-SHA256             | &lt;CompSig&gt;.14  | Falcon512  | SHA256withECDSA | SHA256 |
| id-Falcon512-ECDSA-brainpoolP256r1-SHA256  | &lt;CompSig&gt;.15  | Falcon512  | SHA256withECDSA |SHA256 | 
| id-Falcon512-Ed25519-SHA512            | &lt;CompSig&gt;.16 | Falcon512  | Ed25519| SHA512 |
{: #tab-sig-algs title="Composite Signature Algorithms"}

The table above contains everything needed to implement the listed explicit composite algorithms. See the ASN.1 module in section {{sec-asn1-module}} for the explicit definitions of the above Composite signature algorithms.   


Full specifications for the referenced algorithms can be found as follows:

* _MLDSA_: {{I-D.ietf-lamps-dilithium-certificates}} and [FIPS.204-ipd]
* _ECDSA_: [RFC5480]
* _Ed25519 / Ed448_: [RFC8410]
* _Falcon_: TBD
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
{: #rsa-pss-params3072 title="RSA-PSS 3072 Parameters"}

where:

* `Mask Generation Function (mgf1)` is defined in [RFC8017] 
* `SHA-512` is defined in [RFC6234].


<!-- End of Composite Signature Algorithm section -->


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
  
-  id-Falon512-ECDSA-P256-SHA256
  - Decimal: IANA Assigned
  - Description:  id-Falon512-ECDSA-P256-SHA256
  - References: This Document
  
-  id-Falcon512-ECDSA-brainpoolP256r1-SHA256
  - Decimal: IANA Assigned
  - Description:  id-Falcon512-ECDSA-brainpoolP256r1-SHA256
  - References: This Document     
  
-  id-Falcon512-Ed25519-SHA512
  - Decimal: IANA Assigned
  - Description:  id-Falcon512-Ed25519-SHA512
  - References: This Document               
  

<!-- End of IANA Considerations section -->


# Security Considerations

## Policy for Deprecated and Acceptable Algorithms

Traditionally, a public key, certificate, or signature contains a single cryptographic algorithm. If and when an algorithm becomes deprecated (for example, RSA-512, or SHA1), then clients performing signatures or verifications should be updated to adhere to appropriate policies.

In the composite model this is less obvious since implementers may decide that certain cryptographic algorithms have complementary security properties and are acceptable in combination even though one or both algorithms are deprecated for individual use. As such, a single composite public key or certificate may contain a mixture of deprecated and non-deprecated algorithms.

Since composite algorithms are registered independently of their component algorithms, their deprecation can be handled indpendently from that of their component algorithms. For example a cryptographic policy might continue to allow `id-MLDSA65-ECDSA-P256-SHA256` even after ECDH-P256 is deprecated.


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

Implementors seeking FIPS certification of a composite Signature algorithm where only one of the component algorithms has been FIPS-validated or FIPS-approved should credit the FIPS-validated component algorithm with full security strength, the non-FIPS-validated component algorith with zero security, and the overall composite should be considered full strength and thus FIPS-approved.

The authors wish to note that this gives composite algorithms great future utility both for future cryptographic migrations as well as bridging across jurisdictions; for example defining composite algorithms which combine FIPS cryptography with cryptography from a different national standards body.


## Backwards Compatibility {#sec-backwards-compat}

The term "backwards compatibility" is used here to mean something more specific; that existing systems as they are deployed today can interoperate with the upgraded systems of the future.  This draft explicitly does not provide backwards compatibility, only upgraded systems will understand the OIDs defined in this document.

If backwards compatibility is required, then additional mechanisms will be needed.  Migration and interoperability concerns need to be thought about in the context of various types of protocols that make use of X.509 and PKIX with relation to digital signature objects, from online negotiated protocols such as TLS 1.3 [RFC8446] and IKEv2 [RFC7296], to non-negotiated asynchronous protocols such as S/MIME signed email [RFC8551], document signing such as in the context of the European eIDAS regulations [eIDAS2014], and publicly trusted code signing [codeSigningBRsv2.8], as well as myriad other standardized and proprietary protocols and applications that leverage CMS [RFC5652] signed structures.  Composite simplifies the protocol design work because it can be implemented as a signature algorithm that fits into existing systems.


### Parallel PKIs

We present the term "Parallel PKI" to refer to the setup where a PKI end entity possesses two or more distinct public keys or certificates for the same identity (name), but containing keys for different cryptographic algorithms. One could imagine a set of parallel PKIs where an existing PKI using legacy algorithms (RSA, ECC) is left operational during the post-quantum migration but is shadowed by one or more parallel PKIs using pure post quantum algorithms or composite algorithms (legacy and post-quantum).

Equipped with a set of parallel public keys in this way, a client would have the flexibility to choose which public key(s) or certificate(s) to use in a given signature operation. 

For negotiated protocols, the client could choose which public key(s) or certificate(s) to use based on the negotiated algorithms, or could combine two of the public keys for example in a non-composite hybrid method such as {{I-D.becker-guthrie-noncomposite-hybrid-auth}} or {{I-D.guthrie-ipsecme-ikev2-hybrid-auth}}. Note that it is possible to use the signature algorithms defined in {{sec-alg-ids}} as a way to carry the multiple signature values generated by one of the non-composite public mechanism in protocols where it is easier to support the composite signature algorithms than to implement such a mechanism in the protocol itself. There is also nothing precluding a composite public key from being one of the components used within a non-composite authentication operation; this may lead to greater convenience in setting up parallel PKI hierarchies that need to service a range of clients implementing different styles of post-quantum migration strategies.

For non-negotiated protocols, the details for obtaining backwards compatibility will vary by protocol, but for example in CMS [RFC5652], the inclusion of multiple SignerInfo objects is often already treated as an OR relationship, so including one for each of the signer's parallel PKI public keys would, in many cases, have the desired effect of allowing the receiver to choose one they are compatible with and ignore the others, thus achieving full backwards compatibility.

### Hybrid Extensions (Keys and Signatures)
The use of Composite Crypto provides the possibility to process multiple algorithms without changing the logic of applications, but updating the cryptographic libraries: one-time change across the whole system. However, when it is not possible to upgrade the crypto engines/libraries, it is possible to leverage X.509 extensions to encode the additional keys and signatures. When the custom extensions are not marked critical, although this approach provides the most
backward-compatible approach where clients can simply ignore the post-quantum (or extra) keys and signatures, it also requires
all applications to be updated for correctly processing multiple algorithms together. 


<!-- End of Implementation Considerations section -->



# Intellectual Property Considerations

The following IPR Disclosure relates to this draft:

https://datatracker.ietf.org/ipr/3588/



# Contributors and Acknowledgements
This document incorporates contributions and comments from a large group of experts. The Editors would especially like to acknowledge the expertise and tireless dedication of the following people, who attended many long meetings and generated millions of bytes of electronic mail and VOIP traffic over the past year in pursuit of this document:

Scott Fluhrer (Cisco Systems),
Daniel Van Geest (ISARA),
Britta Hale,
Tim Hollebeek (Digicert),
Panos Kampanakis (Cisco Systems),
Richard Kisley (IBM),
Serge Mister (Entrust),
François Rousseau,
Falko Strenzke and
Felipe Ventura (Entrust)

We are grateful to all, including any contributors who may have
been inadvertently omitted from this list.

This document borrows text from similar documents, including those referenced below. Thanks go to the authors of those
   documents.  "Copying always makes things easier and less error prone" - [RFC8411].

## Making contributions

Additional contributions to this draft are welcome. Please see the working copy of this draft at, as well as open issues at:

https://github.com/EntrustCorporation/draft-ounsworth-composite-sigs

<!-- End of Contributors section -->
