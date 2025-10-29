#!/usr/bin/env python3

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding
import secrets
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_der_public_key

import sys
import datetime
import base64
import json
import textwrap
from zipfile import ZipFile

from pyasn1.type import univ, tag, namedtype
from pyasn1_alt_modules import rfc4055, rfc5208, rfc5280
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

VERSION_IMPLEMENTED = "draft-ietf-lamps-pq-composite-sigs-09"

OID_TABLE = {
    "sha256WithRSAEncryption": univ.ObjectIdentifier((1,2,840,113549,1,1,11)),
    "sha384WithRSAEncryption": univ.ObjectIdentifier((1,2,840,113549,1,1,12)),
    "id-RSASSA-PSS": univ.ObjectIdentifier((1,2,840,113549,1,1,10)),
    "ecdsa-with-SHA256": univ.ObjectIdentifier((1,2,840,10045,4,3,2)),
    "ecdsa-with-SHA384": univ.ObjectIdentifier((1,2,840,10045,4,3,3)),
    "id-Ed25519": univ.ObjectIdentifier((1,3,101,112)),
    "id-Ed448": univ.ObjectIdentifier((1,3,101,113)),
    "id-ML-DSA-44": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,17)),
    "id-ML-DSA-65": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18)),
    "id-ML-DSA-87": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,19)),
    "id-MLDSA44-RSA2048-PSS-SHA256": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,37)),
    "id-MLDSA44-RSA2048-PKCS15-SHA256": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,38)),
    "id-MLDSA44-Ed25519-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,39)),
    "id-MLDSA44-ECDSA-P256-SHA256": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,40)),
    "id-MLDSA65-RSA3072-PSS-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,41)),
    "id-MLDSA65-RSA3072-PKCS15-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,42)),
    "id-MLDSA65-RSA4096-PSS-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,43)),
    "id-MLDSA65-RSA4096-PKCS15-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,44)),
    "id-MLDSA65-ECDSA-P256-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,45)),
    "id-MLDSA65-ECDSA-P384-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,46)),
    "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,47)),
    "id-MLDSA65-Ed25519-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,48)),
    "id-MLDSA87-ECDSA-P384-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,49)),
    "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,50)),
    "id-MLDSA87-Ed448-SHAKE256": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,51)),
    "id-MLDSA87-RSA3072-PSS-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,52)),
    "id-MLDSA87-RSA4096-PSS-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,53)),
    "id-MLDSA87-ECDSA-P521-SHA512": univ.ObjectIdentifier((1,3,6,1,5,5,7,6,54)),
}

PURE_SEED_ALGS = [
    "id-ML-DSA-44",
    "id-ML-DSA-65",
    "id-ML-DSA-87",
]

class SIG:
  pk = None
  sk = None
  params_asn = None

  # returns nothing
  def keyGen(self):
    raise Exception("Not implemented")
    
  # returns (s)
  def sign(self, m):
    raise Exception("Not implemented")

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m):
    raise Exception("Not implemented")

  def public_key_bytes(self):
    raise Exception("Not implemented")
  
  def constructSPKI(self, pkbytes):
   """
   Construct a SubjectPublicKeyInfo using the DER-encoded AlgorithmIdentifier encoded in self.algid, and the provided public key bytes.
   """
   spki = rfc5280.SubjectPublicKeyInfo()
   spki['algorithm'], _ = der_decode(bytes.fromhex(self.algid), asn1Spec=rfc5280.AlgorithmIdentifier())
   spki['subjectPublicKey'] = univ.BitString(hexValue=pkbytes.hex())
   return der_encode(spki)
  
  def loadPK(self, pkbytes):
    spki = self.constructSPKI(pkbytes)
    self.pk = load_der_public_key(spki)

  def private_key_bytes(self):
    raise Exception("Not implemented")
    


class RSA(SIG):
  component_name = "RSA"

  # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=self.key_size)
    self.pk = self.sk.public_key()

  def get_padding(self):
    raise Exception("Not implemented")

  # returns (s)
  def sign(self, m):
    if self.sk == None:
      raise Exception("Cannot Sign for a SIG with no SK.")
    
    s = self.sk.sign(
        m,
        self.get_padding(),
        self.hash_alg)
    return s

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m):
    if self.pk == None:
      raise InvalidSignature("Cannot Verify for a SIG with no PK.")
    
    self.pk.verify(
        s, m,
        self.get_padding(),
        self.hash_alg)

  def public_key_bytes(self):
    return self.pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.PKCS1)

  def public_key_max_len(self):
    """
    RSAPublicKey ::= SEQUENCE {
        modulus           INTEGER,  -- n
        publicExponent    INTEGER   -- e
    }
    """
    return (calculate_der_universal_sequence_max_length([
        calculate_der_universal_integer_max_length(self.pk.key_size),  # n
        calculate_der_universal_integer_max_length(self.pk.public_numbers().e.bit_length())  # e = 65537 = 0b1_00000000_00000001
    ]), False)
    
  def loadPK(self, pkbytes):
    super().loadPK(pkbytes)
    assert isinstance(self.pk, rsa.RSAPublicKey)


  def private_key_bytes(self):
    return self.sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())

  def private_key_max_len(self):
    """
    RSAPrivateKey::= SEQUENCE {
        version Version,
        modulus           INTEGER,  --n
        publicExponent INTEGER,  --e
        privateExponent INTEGER,  --d
        prime1 INTEGER,  --p
        prime2 INTEGER,  --q
        exponent1 INTEGER,  --d mod(p - 1)
        exponent2 INTEGER,  --d mod(q - 1)
        coefficient INTEGER,  --(inverse of q) mod p
        otherPrimeInfos OtherPrimeInfos OPTIONAL
    }
    """
    return (calculate_der_universal_sequence_max_length([
        calculate_der_universal_integer_max_length(max_size_in_bits=1),  # version must be 1 for Composite ML-DSA
        calculate_der_universal_integer_max_length(self.sk.key_size),  # n
        calculate_der_universal_integer_max_length(self.pk.public_numbers().e.bit_length()),  # e = 65537 = 0b1_00000000_00000001
        calculate_der_universal_integer_max_length(self.sk.key_size),  # d
        calculate_der_universal_integer_max_length(self.sk.key_size // 2),  # p
        calculate_der_universal_integer_max_length(self.sk.key_size // 2),  # q
        calculate_der_universal_integer_max_length(self.sk.key_size // 2),  # d mod (p-1)
        calculate_der_universal_integer_max_length(self.sk.key_size // 2),  # d mod (q-1)
        calculate_der_universal_integer_max_length(self.sk.key_size // 2)   # (inverse of q) mod p
        # OtherPrimeInfos are not allowed in Composite ML-DSA
    ]), False)

  def signature_max_len(self):
    return (size_in_bits_to_size_in_bytes(self.sk.key_size), True)
    
class RSAPSS(RSA):
  id = "id-RSASSA-PSS"
  def get_padding(self):
    return padding.PSS(
        mgf=padding.MGF1(self.hash_alg),
        salt_length=padding.PSS.DIGEST_LENGTH)


class RSAPKCS15(RSA):
  def get_padding(self):
    return padding.PKCS1v15()


class RSA2048PSS(RSAPSS):
  key_size = 2048
  hash_alg = hashes.SHA256()
  params_asn = rfc4055.rSASSA_PSS_SHA256_Params
  algid = "30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01 08 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A2 03 02 01 20"


class RSA2048PKCS15(RSAPKCS15):
  id = "sha256WithRSAEncryption"
  key_size = 2048
  hash_alg = hashes.SHA256()
  algid = "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00"


class RSA3072PSS(RSAPSS):
  key_size = 3072
  hash_alg = hashes.SHA256()
  params_asn = rfc4055.rSASSA_PSS_SHA256_Params
  algid = "30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01 08 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A2 03 02 01 20"


class RSA3072PKCS15(RSAPKCS15):
  id = "sha256WithRSAEncryption"
  key_size = 3072
  hash_alg = hashes.SHA256()
  algid = "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00"


class RSA4096PSS(RSAPSS):
  key_size = 4096
  hash_alg = hashes.SHA384()
  params_asn = rfc4055.rSASSA_PSS_SHA384_Params
  algid = "30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01 08 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 A2 03 02 01 30"


class RSA4096PKCS15(RSAPKCS15):
  id = "sha384WithRSAEncryption"
  key_size = 4096
  hash_alg = hashes.SHA384()
  algid = "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00"


class Version(univ.Integer):
    pass

class ECDSAPrivateKey(univ.Sequence):
    parameters = univ.ObjectIdentifier().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('privateKey', univ.OctetString()),
        namedtype.NamedType('parameters', parameters
      )
    )

class ECDSA(SIG):
  component_name = "ECDSA"

  def keyGen(self):
    self.sk = ec.generate_private_key(self.curve)
    self.pk = self.sk.public_key()

  def sign(self, m):    
    s = self.sk.sign(m, ec.ECDSA(self.hash))
    return s

  def verify(self, s, m):
    return self.pk.verify(s, m, ec.ECDSA(self.hash))

  def public_key_bytes(self):
    return self.pk.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint)
        
  def public_key_max_len(self):  
    return (1 + 2 * size_in_bits_to_size_in_bytes(self.curve.key_size), True)

  def private_key_bytes(self):
    prk = ECDSAPrivateKey()
    prk['version'] = 1
    prk['privateKey'] = self.sk.private_numbers().private_value.to_bytes((self.sk.key_size + 7) // 8)
    prk['parameters'] = ECDSAPrivateKey.parameters.clone(self.curveOid)
    return der_encode(prk)
        
  def private_key_max_len(self):
    """
    ECPrivateKey ::= SEQUENCE {
      version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
      privateKey     OCTET STRING,
      parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
      publicKey  [1] BIT STRING OPTIONAL
    }
    """
    return (calculate_der_universal_sequence_max_length([
        calculate_der_universal_integer_max_length(max_size_in_bits=1),  # version must be 1
        calculate_der_universal_octet_string_max_length(size_in_bits_to_size_in_bytes(self.curve.key_size)),  # privateKey
        len(der_encode(ECDSAPrivateKey.parameters.clone(self.curveOid))) # ECParameters
        # publicKey is not allowed in Composite ML-DSA
    ]), True)

  def signature_max_len(self):
    """
    Ecdsa-Sig-Value  ::=  SEQUENCE  {
     r     INTEGER,
     s     INTEGER  }
    """
    return (calculate_der_universal_sequence_max_length([
        calculate_der_universal_integer_max_length(self.curve.key_size),  # r
        calculate_der_universal_integer_max_length(self.curve.key_size)   # s
    ]), False)

class ECDSAP256(ECDSA):
  id = "ecdsa-with-SHA256"
  component_curve = "secp256r1"
  curve = ec.SECP256R1()
  curveOid = "1.2.840.10045.3.1.7"
  hash = hashes.SHA256()
  algid = "30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07"


class ECDSABP256(ECDSA):
  id = "ecdsa-with-SHA256"
  component_curve = "brainpoolP256r1"
  curve = ec.BrainpoolP256R1()
  curveOid = "1.3.36.3.3.2.8.1.1.7"
  hash = hashes.SHA256()
  algid = "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 07"


class ECDSAP384(ECDSA):
  id = "ecdsa-with-SHA384"
  component_curve = "secp384r1"
  curve = ec.SECP384R1()
  curveOid = "1.3.132.0.34"
  hash = hashes.SHA384()
  algid = "30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22"
  

class ECDSABP384(ECDSA):
  id = "ecdsa-with-SHA384"
  component_curve = "brainpoolP384r1"
  curve = ec.BrainpoolP384R1()
  curveOid = "1.3.36.3.3.2.8.1.1.11"
  hash = hashes.SHA384()
  algid = "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0B"


class ECDSAP521(ECDSA):
  id = "ecdsa-with-SHA512"
  component_curve = "secp521r1"
  curve = ec.SECP521R1()
  curveOid = "1.3.132.0.35"
  hash = hashes.SHA512()
  algid = "30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 23"


class EdDSA(SIG):
  def keyGen(self):
    self.sk = self.edsda_private_key_class.generate()
    self.pk = self.sk.public_key()

  def sign(self, m):
    assert isinstance(m, bytes)
    return self.sk.sign(m)

  def verify(self, s, m):
    assert isinstance(s, bytes)
    assert isinstance(m, bytes)
    
    # raises InvalidSignature
    self.pk.verify(s, m)
  
  def public_key_bytes(self):
    return self.pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
        
  def public_key_max_len(self):
    return (len(self.public_key_bytes()), True)

  def private_key_bytes(self):
    return self.sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
        )
        
  def private_key_max_len(self):
    return (len(self.private_key_bytes()), True)
    
  def signature_max_len(self):
    if isinstance(self, Ed25519):
        key_size = 256
    if isinstance(self, Ed448):
        key_size = 456
    return (2 * size_in_bits_to_size_in_bytes(key_size), True)


class Ed25519(EdDSA):
  id = "id-Ed25519"
  component_name = "Ed25519"
  algid = "30 05 06 03 2B 65 70"
  edsda_private_key_class = ed25519.Ed25519PrivateKey


class Ed448(EdDSA):
  id = "id-Ed448"
  component_name = "Ed448"
  algid = "30 05 06 03 2B 65 71"
  edsda_private_key_class = ed448.Ed448PrivateKey


class MLDSA(SIG):

  def keyGen(self):
    self.sk = secrets.token_bytes(32)
    self.pk, _ = self.ML_DSA_class.key_derive(self.sk)

  def sign(self, m, ctx=b''):    
    assert isinstance(m, bytes)
    _, signingKey = self.ML_DSA_class.key_derive(self.sk)
    return self.ML_DSA_class.sign(signingKey, m, ctx)

  def verify(self, s, m, ctx=b''):
    assert isinstance(s, bytes)
    assert isinstance(m, bytes)
    if not self.ML_DSA_class.verify(self.pk, m, s, ctx):
      raise InvalidSignature()
  
  def public_key_bytes(self):
    return self.pk
    
  def public_key_max_len(self):
    return (len(self.public_key_bytes()), True)
  
  def loadPK(self, pkbytes):
    self.pk = pkbytes

  def private_key_bytes(self):    
    return self.sk
    
  def private_key_max_len(self):
    return (len(self.private_key_bytes()), True)
    
  def signature_max_len(self):    
    if isinstance(self, MLDSA44):
      size = 2420
    elif isinstance(self, MLDSA65):
      size = 3309
    elif isinstance(self, MLDSA87):
      size = 4627
    return (size, True)

class MLDSA44(MLDSA):
  id = "id-ML-DSA-44"
  component_name = "ML-DSA-44"
  ML_DSA_class = ML_DSA_44
  algid = "30 0B 06 09 60 86 48 01 65 03 04 03 11"

class MLDSA65(MLDSA):
  id = "id-ML-DSA-65"
  component_name = "ML-DSA-65"
  ML_DSA_class = ML_DSA_65
  algid = "30 0B 06 09 60 86 48 01 65 03 04 03 12"

class MLDSA87(MLDSA):
  id = "id-ML-DSA-87"
  component_name = "ML-DSA-87"
  ML_DSA_class = ML_DSA_87
  algid = "30 0B 06 09 60 86 48 01 65 03 04 03 13s"


### Composites ###

class CompositeSig(SIG):
  mldsa = None
  tradsig = None
  label = ""
  prefix = bytes.fromhex("436F6D706F73697465416C676F726974686D5369676E61747572657332303235")
  PH = None

  def __init__(self):
    super().__init__()

  def loadPK(self, pkbytes):
    mldsapub, tradpub = self.deserializeKey(pkbytes)
    self.mldsa.loadPK(mldsapub)
    self.tradsig.loadPK(tradpub)
    self.pk = self.serializeKey()


  def keyGen(self):
    self.mldsa.keyGen()
    self.tradsig.keyGen()

    self.pk = self.serializeKey()


  def computeMprime(self, m, ctx, return_intermediates=False ):
    """
    Computes the message representative M'.

    return_intermediates=False is the default mode, and returns a single value: Mprime
    return_intermediates=True facilitates debugging by writing out the intermediate values to a file, and returns a tuple (prefix, label, len_ctx, ctx, ph_m, Mprime)
    """

    h = hashes.Hash(self.PH) 
    h.update(m)
    ph_m = h.finalize()


    # M' :=  Prefix || Label || len(ctx) || ctx || PH(M)
    len_ctx = len(ctx).to_bytes(1, 'big')
    Mprime = self.prefix                 + \
         self.label.encode()                 + \
         len_ctx + \
         ctx                         + \
         ph_m
         
    if return_intermediates:
      return (self.prefix, self.label, len_ctx, ctx, ph_m, Mprime)
    else:
      return Mprime  


  def sign(self, m, ctx=b'', PH=hashes.SHA256()):
    """
    returns (s)
    """    
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)
    
    Mprime = self.computeMprime(m, ctx)

    mldsaSig = self.mldsa.sign( Mprime, ctx=self.label.encode() )
    tradSig = self.tradsig.sign( Mprime )
    
    return self.serializeSignatureValue(mldsaSig, tradSig)
  

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m, ctx=b'', PH=None):
    if self.pk == None:
      raise InvalidSignature("Cannot Verify for a SIG with no PK.")
    
    assert isinstance(s, bytes)
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)

    (mldsaSig, tradSig) = self.deserializeSignatureValue(s)

    Mprime = self.computeMprime(m, ctx)
    
    # both of the components raise InvalidSignature exception on error
    self.mldsa.verify(mldsaSig, Mprime, ctx=self.label.encode())
    self.tradsig.verify(tradSig, Mprime)


  def serializeKey(self):
    """
    (pk1, pk2) -> pk
    """
    mldsaPK = self.mldsa.public_key_bytes()
    tradPK  = self.tradsig.public_key_bytes()
    return mldsaPK + tradPK


  def deserializeKey(self, keyBytes):
    """
    pk -> (pk1, pk2)
    """

    assert isinstance(keyBytes, bytes)

    if isinstance(self.mldsa, MLDSA44):
      return keyBytes[:1312], keyBytes[1312:]
    elif isinstance(self.mldsa, MLDSA65):
      return keyBytes[:1952], keyBytes[1952:]
    elif isinstance(self.mldsa, MLDSA87):
      return keyBytes[:2592], keyBytes[2592:]


  def public_key_bytes(self):
    return self.serializeKey()


  def public_key_max_len(self):
    (maxMLDSA, _) = self.mldsa.public_key_max_len()
    (maxTrad, fixedSizeTrad) = self.tradsig.public_key_max_len()
    return (maxMLDSA + maxTrad, fixedSizeTrad)


  def private_key_bytes(self):
    mldsaSK = self.mldsa.private_key_bytes()
    tradSK  = self.tradsig.private_key_bytes()
    return mldsaSK + tradSK

  
  def private_key_max_len(self):
    (maxMLDSA, _) = self.mldsa.private_key_max_len()
    (maxTrad, fixedSizeTrad) = self.tradsig.private_key_max_len()
    return (maxMLDSA + maxTrad, fixedSizeTrad)
    

  def serializeSignatureValue(self, s1, s2):
    assert isinstance(s1, bytes)
    assert isinstance(s2, bytes)
    return s1 + s2

  def deserializeSignatureValue(self, s):
    """
    Returns (mldsaSig, tradSig)
    """
    assert isinstance(s, bytes)

    if isinstance(self.mldsa, MLDSA44):
      mldsaSig = s[:2420]
      tradSig  = s[2420:]
    elif isinstance(self.mldsa, MLDSA65):
      mldsaSig = s[:3309]
      tradSig  = s[3309:]
    elif isinstance(self.mldsa, MLDSA87):
      mldsaSig = s[:4627]
      tradSig  = s[4627:]
  
    return (mldsaSig, tradSig)
   
   
  def signature_max_len(self):
    (maxMLDSA, _) = self.mldsa.signature_max_len()
    (maxTrad, fixedSizeTrad) = self.tradsig.signature_max_len()
    return (maxMLDSA + maxTrad, fixedSizeTrad)


class MLDSA44_RSA2048_PSS_SHA256(CompositeSig):
  id = "id-MLDSA44-RSA2048-PSS-SHA256"
  mldsa = MLDSA44()
  tradsig = RSA2048PSS()
  PH = hashes.SHA256()
  label = "COMPSIG-MLDSA44-RSA2048-PSS-SHA256"


class MLDSA44_RSA2048_PKCS15_SHA256(CompositeSig):
  id = "id-MLDSA44-RSA2048-PKCS15-SHA256"
  mldsa = MLDSA44()
  tradsig = RSA2048PKCS15()
  PH = hashes.SHA256()
  label = "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256"


class MLDSA44_Ed25519_SHA512(CompositeSig):
  id = "id-MLDSA44-Ed25519-SHA512"
  mldsa = MLDSA44()
  tradsig = Ed25519()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA44-Ed25519-SHA512"


class MLDSA44_ECDSA_P256_SHA256(CompositeSig):
  id = "id-MLDSA44-ECDSA-P256-SHA256"
  mldsa = MLDSA44()
  tradsig = ECDSAP256()
  PH = hashes.SHA256()
  label = "COMPSIG-MLDSA44-ECDSA-P256-SHA256"


class MLDSA65_RSA3072_PSS_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA3072-PSS-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA3072PSS()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-RSA3072-PSS-SHA512"


class MLDSA65_RSA3072_PKCS15_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA3072-PKCS15-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA3072PKCS15()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512"


class MLDSA65_RSA4096_PSS_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA4096-PSS-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA4096PSS()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-RSA4096-PSS-SHA512"


class MLDSA65_RSA4096_PKCS15_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA4096-PKCS15-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA4096PKCS15()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512"


class MLDSA65_ECDSA_P256_SHA512(CompositeSig):
  id = "id-MLDSA65-ECDSA-P256-SHA512"
  mldsa = MLDSA65()
  tradsig = ECDSAP256()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-ECDSA-P256-SHA512"


class MLDSA65_ECDSA_P384_SHA512(CompositeSig):
  id = "id-MLDSA65-ECDSA-P384-SHA512"
  mldsa = MLDSA65()
  tradsig = ECDSAP384()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-ECDSA-P384-SHA512"


class MLDSA65_ECDSA_brainpoolP256r1_SHA512(CompositeSig):
  id = "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512"
  mldsa = MLDSA65()
  tradsig = ECDSABP256()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-ECDSA-BP256-SHA512"


class MLDSA65_Ed25519_SHA512(CompositeSig):
  id = "id-MLDSA65-Ed25519-SHA512"
  mldsa = MLDSA65()
  tradsig = Ed25519()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA65-Ed25519-SHA512"


class MLDSA87_ECDSA_P384_SHA512(CompositeSig):
  id = "id-MLDSA87-ECDSA-P384-SHA512"
  mldsa = MLDSA87()
  tradsig = ECDSAP384()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA87-ECDSA-P384-SHA512"


class MLDSA87_ECDSA_brainpoolP384r1_SHA512(CompositeSig):
  id = "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512"
  mldsa = MLDSA87()
  tradsig = ECDSABP384()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA87-ECDSA-BP384-SHA512"


class MLDSA87_Ed448_SHA512(CompositeSig):
  id = "id-MLDSA87-Ed448-SHA512"
  mldsa = MLDSA87()
  tradsig = Ed448()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA87-Ed448-SHA512"


class MLDSA87_Ed448_SHAKE256(CompositeSig):
  id = "id-MLDSA87-Ed448-SHAKE256"
  mldsa = MLDSA87()
  tradsig = Ed448()
  PH = hashes.SHAKE256(64)
  label = "COMPSIG-MLDSA87-Ed448-SHAKE256"


class MLDSA87_RSA3072_PSS_SHA512(CompositeSig):
  id = "id-MLDSA87-RSA3072-PSS-SHA512"
  mldsa = MLDSA87()
  tradsig = RSA3072PSS()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA87-RSA3072-PSS-SHA512"


class MLDSA87_RSA4096_PSS_SHA512(CompositeSig):
  id = "id-MLDSA87-RSA4096-PSS-SHA512"
  mldsa = MLDSA87()
  tradsig = RSA4096PSS()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA87-RSA4096-PSS-SHA512"

  
class MLDSA87_ECDSA_P521_SHA512(CompositeSig):
  id = "id-MLDSA87-ECDSA-P521-SHA512"
  mldsa = MLDSA87()
  tradsig = ECDSAP521()
  PH = hashes.SHA512()
  label = "COMPSIG-MLDSA87-ECDSA-P521-SHA512"


def getNewInstanceByName(oidName):
    match oidName:
      # include pure ML-DSA for baseline correctness checks
      case MLDSA44.id:
        return MLDSA44()
      case MLDSA65.id:
        return MLDSA65()
      case MLDSA87.id:
        return MLDSA87()
      
      # Composites
      case MLDSA44_RSA2048_PSS_SHA256.id:
        return MLDSA44_RSA2048_PSS_SHA256()
      
      case MLDSA44_RSA2048_PKCS15_SHA256.id:
        return MLDSA44_RSA2048_PKCS15_SHA256()
      
      case MLDSA44_Ed25519_SHA512.id:
        return MLDSA44_Ed25519_SHA512()
      
      case MLDSA44_ECDSA_P256_SHA256.id:
        return MLDSA44_ECDSA_P256_SHA256()
      
      case MLDSA65_RSA3072_PSS_SHA512.id:
        return MLDSA65_RSA3072_PSS_SHA512()
      
      case MLDSA65_RSA3072_PKCS15_SHA512.id:
        return MLDSA65_RSA3072_PKCS15_SHA512()
      
      case MLDSA65_RSA4096_PSS_SHA512.id:
        return MLDSA65_RSA4096_PSS_SHA512()
      
      case MLDSA65_RSA4096_PKCS15_SHA512.id:
        return MLDSA65_RSA4096_PKCS15_SHA512()
      
      case MLDSA65_ECDSA_P256_SHA512.id:
        return MLDSA65_ECDSA_P256_SHA512()
      
      case MLDSA65_ECDSA_P384_SHA512.id:
        return MLDSA65_ECDSA_P384_SHA512()
      
      case MLDSA65_ECDSA_brainpoolP256r1_SHA512.id:
        return MLDSA65_ECDSA_brainpoolP256r1_SHA512()
      
      case MLDSA65_Ed25519_SHA512.id:
        return MLDSA65_Ed25519_SHA512()
      
      case MLDSA87_ECDSA_P384_SHA512.id:
        return MLDSA87_ECDSA_P384_SHA512()

      case MLDSA87_ECDSA_brainpoolP384r1_SHA512.id:
        return MLDSA87_ECDSA_brainpoolP384r1_SHA512()

      case MLDSA87_Ed448_SHA512.id:
        return MLDSA87_Ed448_SHA512()
      
      case MLDSA87_Ed448_SHAKE256.id:
        return MLDSA87_Ed448_SHAKE256()

      case MLDSA87_RSA3072_PSS_SHA512.id:
        return MLDSA87_RSA3072_PSS_SHA512()

      case MLDSA87_RSA4096_PSS_SHA512.id:
        return MLDSA87_RSA4096_PSS_SHA512()
      
      case MLDSA87_ECDSA_P521_SHA512.id:
        return MLDSA87_ECDSA_P521_SHA512()


### Generate CA Cert and EE Cert ###
caName = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'IETF'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'LAMPS'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'Composite ML-DSA CA')
    ]
  )

# Since we're gonna sign with PQ algs that python cryptography doesn't
# know about, we need to do this manually
# input: a cert that already carries a signature that needs to be replaced
def caSign(cert, caSK):
  certDer = cert.public_bytes(encoding=serialization.Encoding.DER)
  cert_pyasn1, _ = der_decode(certDer, rfc5280.Certificate())

  # Manually set the algID to ML-DSA-65 and re-sign it
  sigAlgID = rfc5280.AlgorithmIdentifier()
  sigAlgID['algorithm'] = univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18))
  cert_pyasn1['tbsCertificate']['signature'] = sigAlgID
  tbs_bytes = der_encode(cert_pyasn1['tbsCertificate'])
  cert_pyasn1['signatureAlgorithm'] = sigAlgID
  cert_pyasn1['signature'] = univ.BitString(hexValue=ML_DSA_65.sign(caSK, tbs_bytes).hex())

  return x509.load_der_x509_certificate(der_encode(cert_pyasn1))


# RFC 9500 section 2.1
# needed to create a X509 with a keytype that python recognizes,
# then we can manually replace it.
_RSA_DUMMY_KEY = serialization.load_pem_private_key("""
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
89FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvNNU
l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjBd9s
B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tSTT3P59
3VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP29vCzx/+
dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLrweomlGezI
FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/kvrg+Br1l77J
aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa2YErtRjc1/5B2
BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP1O2A3X8hKdXPyrx
IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoHsVunkEJ3vjLP3lyI/
fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2vbWmV2j6rZCg5r/AS0u
pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9JAIPkv0RBZvR0PMBtbp6nT
Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGaauORzBFpY5lU50CgYEAzPHl
u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/SmQh6MYAv1I9bLGwrb3WW/7kqIoD
fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy7/+VE01ZQM5FdY8wiYCQiVZYju9X
Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE
k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo
qoHzFFi3Qx7MHESQb9qHyolHEMNx6QdsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS
CW9wKApOrnyKJ9nI0HcuZQKBgQCMtoV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ
XwozhH63uMMomUmtSG87Sz1TmrXadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw
AsrZt4zeXNwsH7QXHEJCFnCmqw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r
UjmopwKBgAqB2KYYMUqAOvYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0
2riO4p6BaAdvzXjKeRrGNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5
7d56RZOE+ERK2uz/7JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/3
-----END RSA PRIVATE KEY-----
""".encode(), password=None)



def signSigCert(sig):

  x509_builder = x509.CertificateBuilder()
  name = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'IETF'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'LAMPS'),
        x509.NameAttribute(NameOID.COMMON_NAME, sig.id)
    ]
  )
  x509_builder = x509_builder.subject_name( name )
  x509_builder = x509_builder.issuer_name( name )

  one_day = datetime.timedelta(1, 0, 0)
  x509_builder = x509_builder.not_valid_before(datetime.datetime.today() - one_day)
  x509_builder = x509_builder.not_valid_after(datetime.datetime.today() + (one_day * 3652))
  x509_builder = x509_builder.serial_number(x509.random_serial_number())
  x509_builder = x509_builder.public_key(_RSA_DUMMY_KEY.public_key())

  x509_builder = x509_builder.add_extension( x509.KeyUsage(
                                digital_signature=True,
                                content_commitment=False,
                                key_encipherment=False,
                                data_encipherment=False,
                                key_agreement=False,
                                key_cert_sign=False,
                                crl_sign=False,
                                encipher_only=False,
                                decipher_only=False ), critical=True)

  cert = x509_builder.sign(_RSA_DUMMY_KEY, hashes.SHA256())

  
  # Replace the RSA public key with ML-DSA

  # Extract the Certificate
  cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)
  cert_pyasn1, _ = der_decode(cert_der, rfc5280.Certificate())

  spki = rfc5280.SubjectPublicKeyInfo()
  algid = rfc5280.AlgorithmIdentifier()
  algid['algorithm'] = OID_TABLE[sig.id]
  if sig.params_asn != None:
    algid['parameters'] = sig.params_asn
  spki['algorithm'] = algid
  spki['subjectPublicKey'] = univ.BitString(hexValue=sig.public_key_bytes().hex())
  cert_pyasn1['tbsCertificate']['subjectPublicKeyInfo'] = spki


  # cert = caSign(cert, sig.sk)

  # Manually set the algID to ML-DSA and re-sign it
  sigAlgID = rfc5280.AlgorithmIdentifier()
  sigAlgID['algorithm'] = OID_TABLE[sig.id]
  if sig.params_asn != None:
    sigAlgID['parameters'] = sig.params_asn
  cert_pyasn1['tbsCertificate']['signature'] = sigAlgID
  tbs_bytes = der_encode(cert_pyasn1['tbsCertificate'])
  cert_pyasn1['signatureAlgorithm'] = sigAlgID
  cert_pyasn1['signature'] = univ.BitString(hexValue=sig.sign(tbs_bytes).hex())

  return x509.load_der_x509_certificate(der_encode(cert_pyasn1))


def verifyCert(certder):
  """
  Loads and verifies an X.509 cert. Expects the cert in raw DER.
  """
  try:
    x509obj = x509.load_der_x509_certificate(certder)
  except:
    try:
      x509obj = x509.load_pem_x509_certificate(certder)
    except:
      raise ValueError("Input could not be parsed as a DER or PEM certificate.")
    
  OID = univ.ObjectIdentifier(x509obj.signature_algorithm_oid.dotted_string)
  OIDname = [key for key, val in OID_TABLE.items() if val == OID]
  if OIDname == []:
   raise LookupError("OID does not represent a composite (at least not of this version of the draft): "+str(OID))
  OIDname = OIDname[0]

  if x509obj.signature_algorithm_oid != x509obj.public_key_algorithm_oid:
    raise ValueError("Certificate is not signed with the same algorithm as the public key.")

  compAlg = getNewInstanceByName(OIDname)

  if compAlg == None:
    raise LookupError("OID does not represent a composite (at least not of this version of the draft): "+str(OID))


  # python.cryptography.x509 won't give me a raw public key if it doesn't have a class for it.
  # So let's parse this with pyasn1_alt_modules and pull the pk out that way
  asn1Certificate, rest = der_decode( x509obj.public_bytes(serialization.Encoding.DER), asn1Spec=rfc5280.Certificate())
  pubkey = asn1Certificate["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"].asOctets()

  compAlg.loadPK(pubkey)

  try:
    compAlg.verify(x509obj.signature, x509obj.tbs_certificate_bytes)
  except InvalidSignature:
    return False
  
  return True
  


def formatResults(sig, s ):

  jsonTest = {}
  jsonTest['tcId'] = sig.id
  jsonTest['pk'] = base64.b64encode(sig.public_key_bytes()).decode('ascii')

  cert = signSigCert(sig)
  jsonTest['x5c'] = base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')

  jsonTest['sk'] = base64.b64encode(sig.private_key_bytes()).decode('ascii')

  # Construct PKCS#8
  pki = rfc5208.PrivateKeyInfo()
  pki['version'] = 0
  algId = rfc5208.AlgorithmIdentifier()
  algId['algorithm'] = OID_TABLE[sig.id]
  pki['privateKeyAlgorithm'] = algId
  # for standalone ML-DSA, we need to wrap the private key in an OCTET STRING, but not when it's a composite
  if sig.id in ("id-ML-DSA-44", "id-ML-DSA-65", "id-ML-DSA-87"):
    pki['privateKey'] = univ.OctetString(der_encode(univ.OctetString(sig.private_key_bytes()).subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))))
  else:
    pki['privateKey'] = univ.OctetString(sig.private_key_bytes())
  jsonTest['sk_pkcs8'] = base64.b64encode(der_encode(pki)).decode('ascii')

  jsonTest['s'] = base64.b64encode(s).decode('ascii')

  return jsonTest


def output_artifacts_certs_r5(jsonTestVectors):

  artifacts_zip = ZipFile('artifacts_certs_r5.zip', mode='w')

  for tc in jsonTestVectors['tests']:
      try:
          # <friendlyname>-<oid>_ta.der
          if tc['tcId'] in PURE_SEED_ALGS:
            priv_key_type = "seed"
          else:
            priv_key_type = "priv"

          certFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_ta.der"
          rawKeyFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_" + priv_key_type + ".raw"
          derKeyFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_" + priv_key_type + ".der"
      except KeyError:
          # if this one is not in the OID_TABLE, then just skip it
          continue
      
      artifacts_zip.writestr(certFilename, data=base64.b64decode(tc['x5c']))
      artifacts_zip.writestr(rawKeyFilename, data=base64.b64decode(tc['sk']))
      artifacts_zip.writestr(derKeyFilename, data=base64.b64decode(tc['sk_pkcs8']))



# Setup the test vector output

# This is the raw message to be signed for the test vectors
_m = b'The quick brown fox jumps over the lazy dog.'

testVectorOutput = {}
testVectorOutput['m'] = base64.b64encode(_m).decode('ascii')
testVectorOutput['tests'] = []

SIZE_TABLE = {}

ALG_PARAMS_TABLE = {}


def doSig(sig, includeInTestVectors=True, includeInAlgParamsTable=True, includeInSizeTable=True):
  sig.keyGen()
  s = sig.sign(_m)
  sig.verify(s, _m)

  jsonResult = formatResults(sig, s)

  if includeInTestVectors:
    testVectorOutput['tests'].append(jsonResult)

  ALG_PARAMS_TABLE[sig.id] = {}

  if includeInAlgParamsTable:
    ALG_PARAMS_TABLE[sig.id]['render'] = True
    ALG_PARAMS_TABLE[sig.id]['ph'] = type(sig.PH).__name__
    if isinstance(sig.PH, hashes.ExtendableOutputFunction):
      ALG_PARAMS_TABLE[sig.id]['ph'] += "/" + str(sig.PH.digest_size) + "**"
    ALG_PARAMS_TABLE[sig.id]['mldsa'] = sig.mldsa.component_name
    ALG_PARAMS_TABLE[sig.id]['trad'] = sig.tradsig.component_name
    if hasattr(sig.tradsig, 'component_curve'):
      ALG_PARAMS_TABLE[sig.id]['trad_curve'] = sig.tradsig.component_curve
    if hasattr(sig.tradsig, 'key_size'):
      ALG_PARAMS_TABLE[sig.id]['trad_rsa_key_size'] = str(sig.tradsig.key_size)
    ALG_PARAMS_TABLE[sig.id]['trad_sig_alg'] = sig.tradsig.id
    ALG_PARAMS_TABLE[sig.id]['label'] = sig.label

  if includeInSizeTable:
    sizeRow = {}
    sizeRow['pk'] = sig.public_key_max_len()
    sizeRow['sk'] = sig.private_key_max_len()
    sizeRow['s'] = sig.signature_max_len()
    SIZE_TABLE[sig.id] = sizeRow
    
    
def checkTestVectorsSize():
  """
  Checks that the test vectors produced match the sizes advertized in the size table.
  Aborts if it finds a mismatch.
  """
  error = False
  for test in testVectorOutput['tests']:
    alg = test['tcId']
    size = SIZE_TABLE[alg]
    (pkMaxSize, pkFix) = size['pk']
    (skMaxSize, skFix) = size['sk']
    (sMaxSize, sFix)   = size['s']
    pkSize = len(base64.b64decode(test['pk']))
    skSize = len(base64.b64decode(test['sk']))
    sSize  = len(base64.b64decode(test['s']))
    
    
    if pkFix and pkSize != pkMaxSize:
        print("Error: "+alg+" pk size does not match expected: "+str(pkSize)+" != "+str(pkMaxSize)+conditionalAsterisk(not pkFix)+"\n") 
        error = True
    if not pkFix and pkSize > pkMaxSize:
        print("Error: "+alg+" pk size does not match expected: "+str(pkSize)+" > "+str(pkMaxSize)+conditionalAsterisk(not pkFix)+"\n") 
        error = True
    
    if skFix and skSize != skMaxSize:
        print("Error: "+alg+" sk size does not match expected: "+str(skSize)+" != "+str(skMaxSize)+conditionalAsterisk(not skFix)+"\n") 
        error = True
    if not skFix and skSize > skMaxSize:
        print("Error: "+alg+" sk size does not match expected: "+str(skSize)+" > "+str(skMaxSize)+conditionalAsterisk(not skFix)+"\n") 
        error = True
        
    if sFix and sSize != sMaxSize:
        print("Error: "+alg+" s size does not match expected: "+str(sSize)+" != "+str(sMaxSize)+conditionalAsterisk(not sFix)+"\n") 
        error = True
    if not sFix and sSize > sMaxSize:
        print("Error: "+alg+" s size does not match expected: "+str(sSize)+" > "+str(sMaxSize)+conditionalAsterisk(not sFix)+"\n") 
        error = True
    
  if error: sys.exit()
    



    
def writeTestVectors():
  with open('testvectors.json', 'w') as f:
    f.write(json.dumps(testVectorOutput, indent=2))
  
  with open('testvectors_wrapped.json', 'w') as f:
    s = json.dumps(testVectorOutput, indent="").split('\n')
    for l in s:
      f.write('\n'.join(textwrap.wrap(l, width=68, replace_whitespace=False, drop_whitespace=False)))
      f.write('\n')
      
  output_artifacts_certs_r5(testVectorOutput)


# Recreate testvectors_wrapped.json with better wrapping:
#   python3 -c 'import generate_test_vectors; generate_test_vectors.rewriteTestVectors()'
def rewriteTestVectors():
  global testVectorOutput
  with open('testvectors.json') as f:
    testVectorOutput = json.load(f)
  writeTestVectors()


def writeDumpasn1Cfg():
  """
  Creates a dumpasn1.cfg file based on the OID mapping table in this script.
  """

  with open('dumpasn1.cfg', 'w') as f:
    f.write("# dumpasn1 Object Identifier configuration file.\n")
    f.write("# Generated by the Composite Signatures reference implementation\n")
    f.write("# available at: https://github.com/lamps-wg/draft-composite-sigs\n")
    f.write("\n")

    for oid in OID_TABLE:
      f.write("OID = "+ str(OID_TABLE[oid]).replace('.', ' ')+"\n")
      f.write("Comment = "+ oid+"\n")
      f.write("Description = "+ oid+"\n")
      f.write("\n")


def conditionalAsterisk(switch):
    if switch:
      return '*'
    else:
      return ' '
      
def writeSizeTable():
  # In this style:
  # | Algorithm | Public key  | Private key | Signature |
  # | --------- | ----------- | ----------- |  -------- |
  # | ML-DSA-44 |     1312    |      32     |    2420   |
  # | ML-DSA-65 |     1952    |      32     |    3309   |
  # | ML-DSA-87 |     2592    |      32     |    4627   |


  with open('sizeTable.md', 'w') as f:
    f.write('| Algorithm                                     |  Public key  |  Private key |  Signature   |\n')
    f.write('| --------------------------------------------- | ------------ | ------------ |  ----------- |\n')

    for alg in SIZE_TABLE:
      row = SIZE_TABLE[alg]
      (pk, pkFix) = row['pk']
      (sk, skFix) = row['sk']
      (s, sFix) = row['s']
      f.write('| '+ alg.ljust(46, ' ') +'|'+
                 (str(pk)+conditionalAsterisk(not pkFix)).center(14, ' ') +'|'+
                 (str(sk)+conditionalAsterisk(not skFix)).center(14, ' ') +'|'+
                 (str(s)+conditionalAsterisk(not sFix)).center(14, ' ') +'|\n' )
      
      
def writeAlgParams():
  """
  Writes the sets of all algorithm to go into the draft.
  """

  with open('algParams.md', 'w') as f:
    for alg in ALG_PARAMS_TABLE.keys():
      if ALG_PARAMS_TABLE[alg] != {} and ALG_PARAMS_TABLE[alg]['render']:  # boolean controlling rendering in this table.
        f.write("- " + alg + "\n")
        f.write("  - OID: " + str(OID_TABLE[alg]) + "\n")
        f.write("  - Label: " + ALG_PARAMS_TABLE[alg]['label'] + "\n")
        f.write("  - Pre-Hash function (PH): " + ALG_PARAMS_TABLE[alg]['ph'] + "\n")
        f.write("  - ML-DSA variant: " + ALG_PARAMS_TABLE[alg]['mldsa'] + "\n")
        f.write("  - Traditional Algorithm: " + ALG_PARAMS_TABLE[alg]['trad'] + "\n")
        f.write("    - Traditional Signature Algorithm: " + ALG_PARAMS_TABLE[alg]['trad_sig_alg'] + "\n")
        if 'trad_curve' in ALG_PARAMS_TABLE[alg]:
          f.write("    - ECDSA curve: " + ALG_PARAMS_TABLE[alg]['trad_curve'] + "\n")
        if 'trad_rsa_key_size' in ALG_PARAMS_TABLE[alg]:
          f.write("    - RSA size: " + ALG_PARAMS_TABLE[alg]['trad_rsa_key_size'] + "\n")
        if ALG_PARAMS_TABLE[alg]['trad_sig_alg'] == "id-RSASSA-PSS":
          if int(ALG_PARAMS_TABLE[alg]['trad_rsa_key_size']) <= 3072:
            f.write("    - RSASSA-PSS parameters: See {{rsa-pss-params2048-3072}}\n")
          else:
            f.write("    - RSASSA-PSS parameters: See {{rsa-pss-params4096}}\n")
        f.write("\n")


def writeMessageFormatExamples(sig, filename,  m=b'', ctx=b''):
  """
  Writes the Message format examples section for the draft
  """
  f = open(filename, 'w')

  f.write("Example of " + sig.id +" construction of M'.\n\n")

  # Compute the values
  sig.keyGen()

  (prefix, label, len_ctx, ctx, ph_m, Mprime) = sig.computeMprime(m, ctx, return_intermediates=True)



  # Dump the values to file
  wrap_width = 67
  f.write("# Inputs:")
  f.write("\n\n")     
  f.write( '\n'.join(textwrap.wrap("M: " + m.hex(), width=wrap_width)) +"\n" )
  if (ctx == b''):
      f.write("ctx: <empty>\n")
  else:
      f.write( '\n'.join(textwrap.wrap("ctx: " + ctx.hex(), width=wrap_width)) +"\n" )
  f.write("\n")
  f.write("# Components of M':\n\n")
  f.write( '\n'.join(textwrap.wrap("Prefix: " + prefix.hex(), width=wrap_width)) +"\n\n" )
  f.write( '\n'.join(textwrap.wrap("Label: " + label, width=wrap_width)) +"\n\n" )
  f.write( '\n'.join(textwrap.wrap("len(ctx): " + len_ctx.hex(), width=wrap_width)) +"\n\n" )
  if (ctx == b''):
      f.write("ctx: <empty>\n")
  else:
      f.write( '\n'.join(textwrap.wrap("ctx: " + ctx.hex(), width=wrap_width)) +"\n\n" )
  f.write( '\n'.join(textwrap.wrap("PH(M): " + ph_m.hex(), width=wrap_width)) +"\n\n" )
  f.write("\n")
  f.write("# Outputs:\n")
  f.write("# M' = Prefix || Label || len(ctx) || ctx || PH(M)\n\n")
  f.write( '\n'.join(textwrap.wrap("M': " + Mprime.hex(), width=wrap_width)) +"\n\n" )


def calculate_length_length(der_byte_count):
    assert der_byte_count >= 0

    if der_byte_count < (1 << 7):  # Short form
        return 1  # 1 byte for length
    elif der_byte_count < (1 << 8):
        return 2  # 1 byte for length + 1 byte for the length value
    elif der_byte_count < (1 << 16):
        return 3  # 1 byte for length + 2 bytes for the length value
    elif der_byte_count < (1 << 24):
        return 4  # 1 byte for length + 3 bytes for the length value
    else:
        return 5  # 1 byte for length + 4 bytes for the length value


def size_in_bits_to_size_in_bytes(size_in_bits):
    return (size_in_bits + 7) // 8


def calculate_der_universal_integer_max_length(max_size_in_bits):
    # DER uses signed integers, so account for possible leading sign bit.
    signed_max_size_in_bits = max_size_in_bits + 1

    max_der_size_in_bytes = size_in_bits_to_size_in_bytes(signed_max_size_in_bits)

    UNIVERSAL_INTEGER_IDENTIFIER_LENGTH = 1

    return UNIVERSAL_INTEGER_IDENTIFIER_LENGTH + calculate_length_length(max_der_size_in_bytes) + max_der_size_in_bytes


def calculate_der_universal_octet_string_max_length(length):
    UNIVERSAL_OCTET_STRING_IDENTIFIER_LENGTH = 1

    return UNIVERSAL_OCTET_STRING_IDENTIFIER_LENGTH + calculate_length_length(length) + length


def calculate_der_universal_sequence_max_length(der_size_of_sequence_elements):
    UNIVERSAL_SEQUENCE_IDENTIFIER_LENGTH = 1

    length = 0

    for element_size in der_size_of_sequence_elements:
        length += element_size

    length += UNIVERSAL_SEQUENCE_IDENTIFIER_LENGTH + calculate_length_length(length)

    return length


def main():
  
  # Single algs - remove these, just for testing
  # doSig(RSA2048PSS(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(RSA2048PKCS1(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(RSA3072PSS(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(RSA3072PKCS1(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(RSA4096PSS(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(RSA4096PKCS1(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(ECDSAP256(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(ECDSABP256(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(ECDSAP384(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(ECDSABP384(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(Ed25519(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  # doSig(Ed448(), includeInTestVectors=True, includeInLabelsTable=False, includeInSizeTable=True )
  doSig(MLDSA44(), includeInTestVectors=True, includeInAlgParamsTable=False, includeInSizeTable=True )
  doSig(MLDSA65(), includeInTestVectors=True, includeInAlgParamsTable=False, includeInSizeTable=True )
  doSig(MLDSA87(), includeInTestVectors=True, includeInAlgParamsTable=False, includeInSizeTable=True )
  
  

  # Composites
  doSig(MLDSA44_RSA2048_PSS_SHA256() )
  doSig(MLDSA44_RSA2048_PKCS15_SHA256() )
  doSig(MLDSA44_Ed25519_SHA512() )
  doSig(MLDSA44_ECDSA_P256_SHA256() )
  doSig(MLDSA65_RSA3072_PSS_SHA512() )
  doSig(MLDSA65_RSA3072_PKCS15_SHA512() )
  doSig(MLDSA65_RSA4096_PSS_SHA512() )
  doSig(MLDSA65_RSA4096_PKCS15_SHA512() )
  doSig(MLDSA65_ECDSA_P256_SHA512() )
  doSig(MLDSA65_ECDSA_P384_SHA512() )
  doSig(MLDSA65_ECDSA_brainpoolP256r1_SHA512() )
  doSig(MLDSA65_Ed25519_SHA512() )
  doSig(MLDSA87_ECDSA_P384_SHA512() )
  doSig(MLDSA87_ECDSA_brainpoolP384r1_SHA512() )
  doSig(MLDSA87_Ed448_SHAKE256() )
  doSig(MLDSA87_RSA3072_PSS_SHA512() )
  doSig(MLDSA87_RSA4096_PSS_SHA512() )
  doSig(MLDSA87_ECDSA_P521_SHA512() )

  checkTestVectorsSize()
  writeTestVectors()
  writeDumpasn1Cfg()
  writeSizeTable()
  writeAlgParams()


  # Write the message representative examples

  writeMessageFormatExamples(MLDSA65_ECDSA_P256_SHA512(), 'messageFormatSample_noctx.md', m=bytes.fromhex("00010203040506070809"), ctx=b'' )

  
  writeMessageFormatExamples(MLDSA65_ECDSA_P256_SHA512(), 'messageFormatSample_ctx.md', m=bytes.fromhex("00010203040506070809"), ctx=bytes.fromhex("0813061205162623") )



if __name__ == "__main__":
  main()
