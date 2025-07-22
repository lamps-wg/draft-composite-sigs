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


import datetime
import base64
import json
import textwrap
from zipfile import ZipFile

from pyasn1.type import univ, tag
from pyasn1_alt_modules import rfc4055, rfc5208, rfc5280
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

VERSION_IMPLEMENTED = "draft-ietf-lamps-pq-composite-sigs-07"

OID_TABLE = {
    "sha256WithRSAEncryption-2048": univ.ObjectIdentifier((1,2,840,113549,1,1,11)),
    "sha256WithRSAEncryption-3072": univ.ObjectIdentifier((1,2,840,113549,1,1,11)),
    "id-RSASSA-PSS-2048": univ.ObjectIdentifier((1,2,840,113549,1,1,10)),
    "id-RSASSA-PSS-3072": univ.ObjectIdentifier((1,2,840,113549,1,1,10)),
    "id-RSASSA-PSS-4096": univ.ObjectIdentifier((1,2,840,113549,1,1,10)),
    "ecdsa-with-SHA256": univ.ObjectIdentifier((1,2,840,10045,4,3,2)),
    "ecdsa-with-SHA384": univ.ObjectIdentifier((1,2,840,10045,4,3,3)),
    "id-Ed25519": univ.ObjectIdentifier((1,3,101,112)),
    "id-Ed448": univ.ObjectIdentifier((1,3,101,113)),
    "id-ML-DSA-44": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,17)),
    "id-ML-DSA-65": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18)),
    "id-ML-DSA-87": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,19)),
    "id-MLDSA44-RSA2048-PSS-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,0)),
    "id-MLDSA44-RSA2048-PKCS15-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,1)),
    "id-MLDSA44-Ed25519-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,2)),
    "id-MLDSA44-ECDSA-P256-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,3)),
    "id-MLDSA65-RSA3072-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,4)),
    "id-MLDSA65-RSA3072-PKCS15-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,5)),
    "id-MLDSA65-RSA4096-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,6)),
    "id-MLDSA65-RSA4096-PKCS15-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,7)),
    "id-MLDSA65-ECDSA-P256-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,8)),
    "id-MLDSA65-ECDSA-P384-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,9)),
    "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,10)),
    "id-MLDSA65-Ed25519-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,11)),
    "id-MLDSA87-ECDSA-P384-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,12)),
    "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,13)),
    "id-MLDSA87-Ed448-SHAKE256": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,14)),
    "id-MLDSA87-RSA3072-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,15)),
    "id-MLDSA87-RSA4096-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,16)),
    "id-MLDSA87-ECDSA-P521-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,9,1,17)),
}


class SIG:
  pk = None
  sk = None
  id = None
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

  def loadPK(self, pkbytes):
    super().loadPK(pkbytes)
    assert isinstance(self.pk, rsa.RSAPublicKey)


  def private_key_bytes(self):
    return self.sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())


class RSAPSS(RSA):
  def get_padding(self):
    return padding.PSS(
        mgf=padding.MGF1(self.hash_alg),
        salt_length=padding.PSS.DIGEST_LENGTH)


class RSAPKCS15(RSA):
  def get_padding(self):
    return padding.PKCS1v15()


class RSA2048PSS(RSAPSS):
  id = "id-RSASSA-PSS-2048"
  key_size = 2048
  hash_alg = hashes.SHA256()
  params_asn = rfc4055.rSASSA_PSS_SHA256_Params
  algid = "30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01 08 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A2 03 02 01 20"


class RSA2048PKCS15(RSAPKCS15):
  id = "sha256WithRSAEncryption-2048"
  key_size = 2048
  hash_alg = hashes.SHA256()
  algid = "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00"


class RSA3072PSS(RSAPSS):
  id = "id-RSASSA-PSS-3072"
  key_size = 3072
  hash_alg = hashes.SHA256()
  params_asn = rfc4055.rSASSA_PSS_SHA256_Params
  algid = "30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01 08 30 0D 06 09 60 86 48 01 65 03 04 02 01 05 00 A2 03 02 01 20"


class RSA3072PKCS15(RSAPKCS15):
  id = "sha256WithRSAEncryption-3072"
  key_size = 3072
  hash_alg = hashes.SHA256()
  algid = "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00"


class RSA4096PSS(RSAPSS):
  id = "id-RSASSA-PSS-4096"
  key_size = 4096
  hash_alg = hashes.SHA384()
  params_asn = rfc4055.rSASSA_PSS_SHA384_Params
  algid = "30 41 06 09 2A 86 48 86 F7 0D 01 01 0A 30 34 A0 0F 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 A1 1C 30 1A 06 09 2A 86 48 86 F7 0D 01 01 08 30 0D 06 09 60 86 48 01 65 03 04 02 02 05 00 A2 03 02 01 30"


class RSA4096PKCS15(RSAPKCS15):
  id = "sha384WithRSAEncryption-4096"
  key_size = 4096
  hash_alg = hashes.SHA384()
  algid = "30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00"


class ECDSA(SIG):
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

  def private_key_bytes(self):    
    return self.sk.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())


class ECDSAP256(ECDSA):
  id = "ecdsa-with-SHA256"
  curve = ec.SECP256R1()
  hash = hashes.SHA256()
  algid = "30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07"


class ECDSABP256(ECDSA):
  id = "ecdsa-with-SHA256"
  curve = ec.BrainpoolP256R1()
  hash = hashes.SHA256()
  algid = "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 07"


class ECDSAP384(ECDSA):
  id = "ecdsa-with-SHA384"
  curve = ec.SECP384R1()
  hash = hashes.SHA384()
  algid = "30 10 06 07 2A 86 48 CE 3D 02 01 06 05 2B 81 04 00 22"
  

class ECDSABP384(ECDSA):
  id = "ecdsa-with-SHA384"
  curve = ec.BrainpoolP384R1()
  hash = hashes.SHA384()
  algid = "30 14 06 07 2A 86 48 CE 3D 02 01 06 09 2B 24 03 03 02 08 01 01 0B"


class ECDSAP521(ECDSA):
  id = "ecdsa-with-SHA512"
  curve = ec.SECP521R1()
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

  def private_key_bytes(self):
    return self.sk.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())


class Ed25519(EdDSA):
  id = "id-Ed25519"
  algid = "30 05 06 03 2B 65 70"
  edsda_private_key_class = ed25519.Ed25519PrivateKey


class Ed448(EdDSA):
  id = "id-Ed448"
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
  
  def loadPK(self, pkbytes):
    self.pk = pkbytes

  def private_key_bytes(self):    
    return self.sk
  

class MLDSA44(MLDSA):
  id = "id-ML-DSA-44"
  ML_DSA_class = ML_DSA_44
  algid = "30 0B 06 09 60 86 48 01 65 03 04 03 11"

class MLDSA65(MLDSA):
  id = "id-ML-DSA-65"
  ML_DSA_class = ML_DSA_65
  algid = "30 0B 06 09 60 86 48 01 65 03 04 03 12"

class MLDSA87(MLDSA):
  id = "id-ML-DSA-87"
  ML_DSA_class = ML_DSA_87
  algid = "30 0B 06 09 60 86 48 01 65 03 04 03 13s"



### Composites ###

class CompositeSig(SIG):
  mldsa = None
  tradsig = None
  domain = ""
  prefix = bytes.fromhex("436F6D706F73697465416C676F726974686D5369676E61747572657332303235")
  PH = None

  def __init__(self):
    super().__init__()
    self.domain = DOMAIN_TABLE[self.id][0]  # the first component is the domain,
                                            # the second is a boolean controlling whether
                                            # this renders in the domsep table in the draft.

  def loadPK(self, pkbytes):
    mldsapub, tradpub = self.deserializeKey(pkbytes)
    self.mldsa.loadPK(mldsapub)
    self.tradsig.loadPK(tradpub)
    self.pk = self.serializeKey()


  def keyGen(self):
    self.mldsa.keyGen()
    self.tradsig.keyGen()

    self.pk = self.serializeKey()


  def computeMprime(self, m, ctx, r, return_intermediates=False ):
    """
    Computes the message representative M'.

    return_intermediates=False is the default mode, and returns a single value: Mprime
    return_intermediates=True facilitates debugging by writing out the intermediate values to a file, and returns a tuple (prefix, domain, len_ctx, ctx, r, ph_m, Mprime)
    """

    h = hashes.Hash(self.PH) 
    h.update(m)
    ph_m = h.finalize()


    # M' :=  Prefix || Domain || len(ctx) || ctx || r || PH(M)
    len_ctx = len(ctx).to_bytes(1, 'big')
    Mprime = self.prefix                 + \
         self.domain                 + \
         len_ctx + \
         ctx                         + \
         r                           + \
         ph_m
         
    if return_intermediates:
      return (self.prefix, self.domain, len_ctx, ctx, r, ph_m, Mprime)
    else:
      return Mprime  


  def sign(self, m, ctx=b'', PH=hashes.SHA256()):
    """
    returns (s)
    """    
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)

    r = secrets.token_bytes(32)
    Mprime = self.computeMprime(m, ctx, r)

    mldsaSig = self.mldsa.sign( Mprime, ctx=self.domain )
    tradSig = self.tradsig.sign( Mprime )
    
    return self.serializeSignatureValue(r, mldsaSig, tradSig)
  

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m, ctx=b'', PH=None):
    if self.pk == None:
      raise InvalidSignature("Cannot Verify for a SIG with no PK.")
    
    assert isinstance(s, bytes)
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)

    (r, mldsaSig, tradSig) = self.deserializeSignatureValue(s)

    if len(r) != 32:
      raise InvalidSignature("r is the wrong length")

    Mprime = self.computeMprime(m, ctx, r)
    
    # both of the components raise InvalidSignature exception on error
    self.mldsa.verify(mldsaSig, Mprime, ctx=self.domain)
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

  def private_key_bytes(self):
    mldsaSK = self.mldsa.private_key_bytes()
    tradSK  = self.tradsig.private_key_bytes()
    return mldsaSK + tradSK

  def serializeSignatureValue(self, r, s1, s2):
    assert isinstance(r, bytes)
    assert len(r) == 32
    assert isinstance(s1, bytes)
    assert isinstance(s2, bytes)
    return r + s1 + s2

  def deserializeSignatureValue(self, s):
    """
    Returns (r, mldsaSig, tradSig)
    """
    assert isinstance(s, bytes)

    r = s[:32]
    s = s[32:]  # truncate off the randomizer

    if isinstance(self.mldsa, MLDSA44):
      mldsaSig = s[:2420]
      tradSig  = s[2420:]
    elif isinstance(self.mldsa, MLDSA65):
      mldsaSig = s[:3309]
      tradSig  = s[3309:]
    elif isinstance(self.mldsa, MLDSA87):
      mldsaSig = s[:4627]
      tradSig  = s[4627:]
  
    return (r, mldsaSig, tradSig)

class MLDSA44_RSA2048_PSS_SHA256(CompositeSig):
  id = "id-MLDSA44-RSA2048-PSS-SHA256"
  mldsa = MLDSA44()
  tradsig = RSA2048PSS()
  PH = hashes.SHA256()


class MLDSA44_RSA2048_PKCS15_SHA256(CompositeSig):
  id = "id-MLDSA44-RSA2048-PKCS15-SHA256"
  mldsa = MLDSA44()
  tradsig = RSA2048PKCS15()
  PH = hashes.SHA256()


class MLDSA44_Ed25519_SHA512(CompositeSig):
  id = "id-MLDSA44-Ed25519-SHA512"
  mldsa = MLDSA44()
  tradsig = Ed25519()
  PH = hashes.SHA512()


class MLDSA44_ECDSA_P256_SHA256(CompositeSig):
  id = "id-MLDSA44-ECDSA-P256-SHA256"
  mldsa = MLDSA44()
  tradsig = ECDSAP256()
  PH = hashes.SHA256()


class MLDSA65_RSA3072_PSS_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA3072-PSS-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA3072PSS()
  PH = hashes.SHA512()


class MLDSA65_RSA3072_PKCS15_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA3072-PKCS15-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA3072PKCS15()
  PH = hashes.SHA512()


class MLDSA65_RSA4096_PSS_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA4096-PSS-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA4096PSS()
  PH = hashes.SHA512()


class MLDSA65_RSA4096_PKCS15_SHA512(CompositeSig):
  id = "id-MLDSA65-RSA4096-PKCS15-SHA512"
  mldsa = MLDSA65()
  tradsig = RSA4096PKCS15()
  PH = hashes.SHA512()


class MLDSA65_ECDSA_P256_SHA512(CompositeSig):
  id = "id-MLDSA65-ECDSA-P256-SHA512"
  mldsa = MLDSA65()
  tradsig = ECDSAP256()
  PH = hashes.SHA512()


class MLDSA65_ECDSA_P384_SHA512(CompositeSig):
  id = "id-MLDSA65-ECDSA-P384-SHA512"
  mldsa = MLDSA65()
  tradsig = ECDSAP384()
  PH = hashes.SHA512()


class MLDSA65_ECDSA_brainpoolP256r1_SHA512(CompositeSig):
  id = "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512"
  mldsa = MLDSA65()
  tradsig = ECDSABP256()
  PH = hashes.SHA512()


class MLDSA65_Ed25519_SHA512(CompositeSig):
  id = "id-MLDSA65-Ed25519-SHA512"
  mldsa = MLDSA65()
  tradsig = Ed25519()
  PH = hashes.SHA512()


class MLDSA87_ECDSA_P384_SHA512(CompositeSig):
  id = "id-MLDSA87-ECDSA-P384-SHA512"
  mldsa = MLDSA87()
  tradsig = ECDSAP384()
  PH = hashes.SHA512()


class MLDSA87_ECDSA_brainpoolP384r1_SHA512(CompositeSig):
  id = "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512"
  mldsa = MLDSA87()
  tradsig = ECDSABP384()
  PH = hashes.SHA512()


class MLDSA87_Ed448_SHA512(CompositeSig):
  id = "id-MLDSA87-Ed448-SHA512"
  mldsa = MLDSA87()
  tradsig = Ed448()
  PH = hashes.SHA512()


class MLDSA87_Ed448_SHAKE256(CompositeSig):
  id = "id-MLDSA87-Ed448-SHAKE256"
  mldsa = MLDSA87()
  tradsig = Ed448()
  PH = hashes.SHAKE256(64)


class MLDSA87_RSA3072_PSS_SHA512(CompositeSig):
  id = "id-MLDSA87-RSA3072-PSS-SHA512"
  mldsa = MLDSA87()
  tradsig = RSA3072PSS()
  PH = hashes.SHA512()


class MLDSA87_RSA4096_PSS_SHA512(CompositeSig):
  id = "id-MLDSA87-RSA4096-PSS-SHA512"
  mldsa = MLDSA87()
  tradsig = RSA4096PSS()
  PH = hashes.SHA512()

  
class MLDSA87_ECDSA_P521_SHA512(CompositeSig):
  id = "id-MLDSA87-ECDSA-P521-SHA512"
  mldsa = MLDSA87()
  tradsig = ECDSAP521()
  PH = hashes.SHA512()


def getNewInstanceByName(oidName):
    match oidName:
      # include pure ML-DSA for baseline correctness checks
      case MLDSA44.id:
        return MLDSA44()
      case MLDSA65.id:
        return MLDSA65()
      case MLDSA87.id:
        return MLDSA87()
      
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
        x509.NameAttribute(NameOID.COMMON_NAME, 'Composite ML-KEM CA')
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
          certFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_ta.der"
          rawKeyFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_priv.raw"
          derKeyFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_priv.der"
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

DOMAIN_TABLE = {}

def genDomainTable():
  """
  This is a bit weird; we have to generate it first because
  this table is used by the composite.sign() to construct Mprime,
  but also not every supported option should be rendered into
  the domain separators table in the draft, hence carrying a boolean.
  By default, everything is False to be included in the table unless
  turned on by doSig(.., includeInDomainTable=True)."""

  for alg in OID_TABLE:
    domain = der_encode(OID_TABLE[alg])
    DOMAIN_TABLE[alg] = (domain, False)

# run this statically
genDomainTable()

def doSig(sig, includeInTestVectors=True, includeInDomainTable=True, includeInSizeTable=True):
  sig.keyGen()
  s = sig.sign(_m)
  sig.verify(s, _m)

  jsonResult = formatResults(sig, s)

  if includeInTestVectors:
    testVectorOutput['tests'].append(jsonResult)

  if includeInDomainTable:
    DOMAIN_TABLE[sig.id] = (DOMAIN_TABLE[sig.id][0], True)

  if includeInSizeTable:
    sizeRow = {}
    sizeRow['pk'] = len(sig.public_key_bytes())
    sizeRow['sk'] = len(sig.private_key_bytes())
    sizeRow['s'] = len(s)
    SIZE_TABLE[sig.id] = sizeRow
    
    
def writeTestVectors():
  with open('testvectors.json', 'w') as f:
    f.write(json.dumps(testVectorOutput, indent=2))
  
  with open('testvectors_wrapped.json', 'w') as f:
    f.write('\n'.join(textwrap.wrap(''.join(json.dumps(testVectorOutput, indent="")), 
                                  width=68,
                                  replace_whitespace=False,
                                  drop_whitespace=False)))
      
  output_artifacts_certs_r5(testVectorOutput)


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
      f.write('| '+ alg.ljust(46, ' ') +'|'+
                 str(row['pk']).center(14, ' ') +'|'+
                 str(row['sk']).center(14, ' ') +'|'+
                 str(row['s']).center(14, ' ') +'|\n' )
      
      
def writeDomainTable():
  """
  Writes the table of domain separators to go into the draft.
  """

  with open('domSepTable.md', 'w') as f:
    f.write('| Composite Signature Algorithm                | Domain Separator (in Hex encoding)|\n')
    f.write('| -------------------------------------------  | --------------------------------- |\n')

    for alg in DOMAIN_TABLE:
      if DOMAIN_TABLE[alg][1]:  # boolean controlling rendering in this table.
        f.write('| ' + alg.ljust(46, ' ') + " | " + base64.b16encode(DOMAIN_TABLE[alg][0]).decode('ASCII') + " |\n")
        

def writeMessageFormatExamples(sig, filename,  m=b'', ctx=b''):
  """
  Writes the Message format examples section for the draft
  """
  f = open(filename, 'w')

  f.write("Example of " + sig.id +" construction of M'.\n\n")

  # Compute the values
  sig.keyGen()

  r = secrets.token_bytes(32)
  (prefix, domain, len_ctx, ctx, r, ph_m, Mprime) = sig.computeMprime(m, ctx, r, return_intermediates=True)



  # Dump the values to file
  wrap_width = 70
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
  f.write( '\n'.join(textwrap.wrap("Domain: " + domain.hex(), width=wrap_width)) +"\n\n" )
  f.write( '\n'.join(textwrap.wrap("len(ctx): " + len_ctx.hex(), width=wrap_width)) +"\n\n" )
  if (ctx == b''):
      f.write("ctx: <empty>\n")
  else:
      f.write( '\n'.join(textwrap.wrap("ctx: " + ctx.hex(), width=wrap_width)) +"\n\n" )
  f.write( '\n'.join(textwrap.wrap("r: " + r.hex(), width=wrap_width)) +"\n" )
  f.write( '\n'.join(textwrap.wrap("PH(M): " + ph_m.hex(), width=wrap_width)) +"\n\n" )
  f.write("\n")
  f.write("# Outputs:\n")
  f.write("# M' = Prefix || Domain || len(ctx) || ctx || r || PH(M)\n\n")
  f.write( '\n'.join(textwrap.wrap("M': " + Mprime.hex(), width=wrap_width)) +"\n\n" )




def main():
  
  # Single algs - remove these, just for testing
  # doSig(RSA2048PSS(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(RSA2048PKCS1(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(RSA3072PSS(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(RSA3072PKCS1(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(RSA4096PSS(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(RSA4096PKCS1(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(ECDSAP256(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(ECDSABP256(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(ECDSAP384(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(ECDSABP384(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(Ed25519(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  # doSig(Ed448(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  doSig(MLDSA44(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  doSig(MLDSA65(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  doSig(MLDSA87(), includeInTestVectors=True, includeInDomainTable=False, includeInSizeTable=True )
  
  

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

  writeTestVectors()
  writeDumpasn1Cfg()
  writeSizeTable()
  writeDomainTable()


  # Write the message representative examples

  writeMessageFormatExamples(MLDSA65_ECDSA_P256_SHA512(), 'messageFormatSample_noctx.md', m=bytes.fromhex("00010203040506070809"), ctx=b'' )

  
  writeMessageFormatExamples(MLDSA65_ECDSA_P256_SHA512(), 'messageFormatSample_ctx.md', m=bytes.fromhex("00010203040506070809"), ctx=bytes.fromhex("0813061205162623") )



if __name__ == "__main__":
  main()
