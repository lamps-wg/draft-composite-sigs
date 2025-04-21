#!/usr/bin/env python3

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448, padding
import secrets
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


import datetime
import base64
import json
import textwrap

from pyasn1.type import univ
from pyasn1_alt_modules import rfc4055, rfc5280
from pyasn1.codec.der.decoder import decode
from pyasn1.codec.der.encoder import encode


OID_TABLE = {
    # "sha256WithRSAEncryption-2048": univ.ObjectIdentifier((1,2,840,113549,1,1,11)),
    # "sha256WithRSAEncryption-3072": univ.ObjectIdentifier((1,2,840,113549,1,1,11)),
    # "id-RSASSA-PSS-2048": univ.ObjectIdentifier((1,2,840,113549,1,1,10)),
    # "id-RSASSA-PSS-3072": univ.ObjectIdentifier((1,2,840,113549,1,1,10)),
    # "id-RSASSA-PSS-4096": univ.ObjectIdentifier((1,2,840,113549,1,1,10)),
    # "ecdsa-with-SHA256": univ.ObjectIdentifier((1,2,840,10045,4,3,2)),
    # "ecdsa-with-SHA384": univ.ObjectIdentifier((1,2,840,10045,4,3,3)),
    # "id-Ed25519": univ.ObjectIdentifier((1,3,101,112)),
    # "id-Ed448": univ.ObjectIdentifier((1,3,101,113)),
    "id-ML-DSA-44": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,17)),
    "id-ML-DSA-65": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18)),
    "id-ML-DSA-87": univ.ObjectIdentifier((2,16,840,1,101,3,4,3,19)),
    "id-MLDSA44-RSA2048-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,60)),
    "id-MLDSA44-RSA2048-PKCS15": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,61)),
    "id-MLDSA44-Ed25519": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,62)),
    "id-MLDSA44-ECDSA-P256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,63)),
    "id-MLDSA65-RSA3072-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,64)),
    "id-MLDSA65-RSA3072-PKCS15": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,65)),
    "id-MLDSA65-RSA4096-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,66)),
    "id-MLDSA65-RSA4096-PKCS15": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,67)),
    "id-MLDSA65-ECDSA-P256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,68)),
    "id-MLDSA65-ECDSA-P384": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,69)),
    "id-MLDSA65-ECDSA-brainpoolP256r1": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,70)),
    "id-MLDSA65-Ed25519": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,71)),
    "id-MLDSA87-ECDSA-P384": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,72)),
    "id-MLDSA87-ECDSA-brainpoolP384r1": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,73)),
    "id-MLDSA87-Ed448": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,74)),
    "id-MLDSA87-RSA4096-PSS": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,75)),
    "id-HashMLDSA44-RSA2048-PSS-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,80)),
    "id-HashMLDSA44-RSA2048-PKCS15-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,81)),
    "id-HashMLDSA44-Ed25519-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,82)),
    "id-HashMLDSA44-ECDSA-P256-SHA256": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,83)),
    "id-HashMLDSA65-RSA3072-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,84)),
    "id-HashMLDSA65-RSA3072-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,85)),
    "id-HashMLDSA65-RSA4096-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,86)),
    "id-HashMLDSA65-RSA4096-PKCS15-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,87)),
    "id-HashMLDSA65-ECDSA-P256-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,88)),
    "id-HashMLDSA65-ECDSA-P384-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,89)),
    "id-HashMLDSA65-ECDSA-brainpoolP256r1-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,90)),
    "id-HashMLDSA65-Ed25519-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,91)),
    "id-HashMLDSA87-ECDSA-P384-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,92)),
    "id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,93)),
    "id-HashMLDSA87-RSA4096-PSS-SHA512": univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,95))
}

class SIG:
  pk = None
  sk = None
  id = None
  oid = None
  pss_params = None
  pss_params_asn = None

  # returns nothing
  def keyGen(self):
    pass
    
  # returns (s)
  def sign(self, m):
    if self.sk == None:
      raise Exception("Cannot Sign for a SIG with no SK.")
    pass

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m):
    if self.pk == None:
      raise Exception("Cannot Verify for a SIG with no PK.")
    pass

  def public_key_bytes(self):
    raise Exception("Not implemented")

  def private_key_bytes(self):
    raise Exception("Not implemented")
    


class RSA2048PSS(SIG):
  id = "id-RSASSA-PSS-2048"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1,10))
  pss_params = padding.PSS(
                              mgf=padding.MGF1(hashes.SHA256()),
                              salt_length=padding.PSS.MAX_LENGTH
                          )
  pss_params_asn = rfc4055.rSASSA_PSS_SHA256_Params

  # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
      )
    self.pk = self.sk.public_key()
    
  # returns (s)
  def sign(self, m):
    if self.sk == None:
      raise Exception("Cannot Sign for a SIG with no SK.")
    
    s = self.sk.sign(
                        m,
                        self.pss_params,
                        hashes.SHA256()
                    )
    return s

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m):
    if self.pk == None:
      raise Exception("Cannot Verify for a SIG with no PK.")
    
    self.pk.verify(
                      s,
                      m,
                      self.pss_params,
                      hashes.SHA256()
                  )


  def public_key_bytes(self):
    return self.pk.public_bytes(
                      encoding=serialization.Encoding.DER,
                      format=serialization.PublicFormat.PKCS1
                    )


  def private_key_bytes(self):
    return self.sk.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )


class RSA2048PKCS15(RSA2048PSS):
  id = "sha256WithRSAEncryption-2048"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1,11))

    # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
      )
    self.pk = self.sk.public_key()

  # returns (s)
  def sign(self, m):
    if self.sk == None:
      raise Exception("Cannot Sign for a SIG with no SK.")
    
    s = self.sk.sign(
                        m,
                        padding.PKCS1v15(),
                        hashes.SHA256()
                    )
    return s

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m):
    if self.pk == None:
      raise Exception("Cannot Verify for a SIG with no PK.")
    
    self.pk.verify(
                      s,
                      m,
                      padding.PKCS1v15(),
                      hashes.SHA256()
                  )


class RSA3072PSS(RSA2048PSS):
  id = "id-RSASSA-PSS-3072"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1,10))

  # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
      )
    self.pk = self.sk.public_key()
    
  # the rest of the functions are inherited from RSA2048PSS


class RSA3072PKCS15(RSA2048PKCS15):
  id = "sha256WithRSAEncryption-3072"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1,10))

    # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072
      )
    self.pk = self.sk.public_key()


class RSA4096PSS(RSA2048PSS):
  id = "id-RSASSA-PSS-4096"
  oid = univ.ObjectIdentifier((1,2,840,113549,1,1,10))

  # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
      )
    self.pk = self.sk.public_key()
    
  # the rest of the functions are inherited from RSA2048PSS


class RSA4096PKCS15(RSA2048PKCS15):
  id = "sha256WithRSAEncryption-4096"

    # returns nothing
  def keyGen(self):
    self.sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
      )
    self.pk = self.sk.public_key()



class ECDSAP256(SIG):
  id = "ecdsa-with-SHA256"
  oid = univ.ObjectIdentifier((1,2,840,10045,4,3,2))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.SECP256R1())
    self.pk = self.sk.public_key()
    
  def sign(self, m):    
    s = self.sk.sign(m, ec.ECDSA(hashes.SHA256()))
    return s

  def verify(self, s, m):
    return self.pk.verify(s, m, ec.ECDSA(hashes.SHA256()))
  

  def public_key_bytes(self):
    return self.pk.public_bytes(
                      encoding=serialization.Encoding.X962,
                      format=serialization.PublicFormat.UncompressedPoint
                    )

  def private_key_bytes(self):    
    return self.sk.private_bytes(
                        encoding=serialization.Encoding.DER,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )

class ECDSABP256(ECDSAP256):
  id = "ecdsa-with-SHA256"
  oid = univ.ObjectIdentifier((1,2,840,10045,4,3,2))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.BrainpoolP256R1())
    self.pk = self.sk.public_key()



class ECDSAP384(ECDSAP256):
  id = "ecdsa-with-SHA384"
  oid = univ.ObjectIdentifier((1,2,840,10045,4,3,3))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.SECP384R1())
    self.pk = self.sk.public_key()
    
  def sign(self, m):    
    s = self.sk.sign(m, ec.ECDSA(hashes.SHA384()))
    return s

  def verify(self, s, m):
    return self.pk.verify(s, m, ec.ECDSA(hashes.SHA384()))
  

class ECDSABP384(ECDSAP384):
  id = "ecdsa-with-SHA384"
  oid = univ.ObjectIdentifier((1,2,840,10045,4,3,3))

  def keyGen(self):
    self.sk = ec.generate_private_key(ec.BrainpoolP384R1())
    self.pk = self.sk.public_key()


class Ed25519(SIG):
  id = "id-Ed25519"
  oid = univ.ObjectIdentifier((1,3,101,112))

  def keyGen(self):
    self.sk = ed25519.Ed25519PrivateKey.generate()
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
                      format=serialization.PublicFormat.Raw
                    )


  def private_key_bytes(self):
    return self.sk.private_bytes(
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )

class Ed448(Ed25519):
  id = "id-Ed448"
  oid = univ.ObjectIdentifier((1,3,101,113))

  def keyGen(self):
    self.sk = ed448.Ed448PrivateKey.generate()
    self.pk = self.sk.public_key()



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

  def private_key_bytes(self):    
    return self.sk
  

class MLDSA44(MLDSA):
  id = "id-ML-DSA-44"
  oid = univ.ObjectIdentifier((2,16,840,1,101,3,4,3,17))
  ML_DSA_class = ML_DSA_44

class MLDSA65(MLDSA):
  id = "id-ML-DSA-65"
  oid = univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18))
  ML_DSA_class = ML_DSA_65

class MLDSA87(MLDSA):
  id = "id-ML-DSA-87"
  oid = univ.ObjectIdentifier((2,16,840,1,101,3,4,3,19))
  ML_DSA_class = ML_DSA_87



### Composites ###

class CompositeSig(SIG):
  mldsa = None
  tradsig = None
  domain = ""
  prefix = "436F6D706F73697465416C676F726974686D5369676E61747572657332303235"

  def keyGen(self):
    self.mldsa.keyGen()
    self.tradsig.keyGen()

    self.pk = self.public_key_bytes()
    self.sk = self.public_key_bytes()  


  def computeMp(self, m, ctx):
    # M' = Prefix || Domain || len(ctx) || ctx || M
    Mp = bytes.fromhex(self.prefix)  + \
         bytes.fromhex(self.domain)  + \
         len(ctx).to_bytes(1, 'big') + \
         ctx                         + \
         m
    
    return Mp

  def sign(self, m, ctx=b''):
    """
    returns (s)
    """
    if self.sk == None:
      raise Exception("Cannot Sign for a SIG with no SK.")
    
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)

    Mp = self.computeMp(m, ctx)

    mldsaSig = self.mldsa.sign( Mp, ctx=bytes.fromhex(self.domain) )
    tradSig = self.tradsig.sign( Mp )
    
    return self.serializeSignatureValue(mldsaSig, tradSig)
  

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m, ctx=b''):
    if self.pk == None:
      raise Exception("Cannot Verify for a SIG with no PK.")
    
    assert isinstance(s, bytes)
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)

    (mldsaS, tradS) = self.deserializeSignatureValue(s)

    Mp = self.computeMp(m, ctx)
    
    # both of the components raise InvalidSignature exception on error
    self.mldsa.verify(mldsaS, Mp, ctx=bytes.fromhex(self.domain))
    self.tradsig.verify(tradS, Mp)


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
  

  # def compositeEncode(self, v1, v2):
  #   """
  #   (v1, v2) -> v
  #   """
  #   assert isinstance(v1, bytes)
  #   assert isinstance(v2, bytes)
  #   return len(v1).to_bytes(4, 'big') + v1 + v2
  

  # def compositeDecode(self, v):
  #   """
  #   v -> (v1, v2)
  #   """
  #   assert isinstance(v, bytes)
  #   # first 4 bytes is the length tag of ct1
  #   v1_len = int.from_bytes(v[0:4], 'big')
  #   v1 = v[4:4+v1_len]
  #   v2 = v[4+v1_len:]
  #   return (v1, v2)
  

  def serializeSignatureValue(self, s1, s2):
    assert isinstance(s1, bytes)
    assert isinstance(s2, bytes)
    return s1 + s2
  

  def deserializeSignatureValue(self, s):
    assert isinstance(s, bytes)

    if isinstance(self.mldsa, MLDSA44):
      return s[:2420], s[2420:]
    elif isinstance(self.mldsa, MLDSA65):
      return s[:3309], s[3309:]
    elif isinstance(self.mldsa, MLDSA87):
      return s[:4627], s[4627:]
    




class HashCompositeSig(CompositeSig):
  mldsa = None
  tradsig = None
  domain = ""
  PH = None
  prefix = "436F6D706F73697465416C676F726974686D5369676E61747572657332303235"

  def computeMp(self, m, ctx):

    if (self.PH.name == hashes.SHA256.name):
      HashOID = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01'
      h = hashes.Hash(hashes.SHA256())
    elif (self.PH.name == hashes.SHA512.name):
      HashOID = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03'
      h = hashes.Hash(hashes.SHA512())
    elif (self.PH.name == hashes.SHAKE128.name):
      HashOID = b'\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b'
      h = hashes.Hash(hashes.SHAKE128(256))
    # elif ...

    h.update(m)
    ph_m = h.finalize()


    # M' :=  Prefix || Domain || len(ctx) || ctx || HashOID || PH(M)
    Mp = bytes.fromhex(self.prefix)  + \
         bytes.fromhex(self.domain)  + \
         len(ctx).to_bytes(1, 'big') + \
         ctx                         + \
         HashOID                     + \
         ph_m

    return Mp


  def sign(self, m, ctx=b'', PH=hashes.SHA256()):
    """
    returns (s)
    """
    if self.sk == None:
      raise Exception("Cannot Sign for a SIG with no SK.")
    
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)

    Mp = self.computeMp(m, ctx)

    mldsaSig = self.mldsa.sign( Mp, ctx=bytes.fromhex(self.domain) )
    tradSig = self.tradsig.sign( Mp )
    
    return self.serializeSignatureValue(mldsaSig, tradSig)
  

  # raises cryptography.exceptions.InvalidSignature
  def verify(self, s, m, ctx=b'', PH=hashes.SHA256()):
    if self.pk == None:
      raise Exception("Cannot Verify for a SIG with no PK.")
    
    assert isinstance(s, bytes)
    assert isinstance(m, bytes)
    assert isinstance(ctx, bytes)

    (mldsaS, tradS) = self.deserializeSignatureValue(s)

    Mp = self.computeMp(m, ctx)
    
    # both of the components raise InvalidSignature exception on error
    self.mldsa.verify(mldsaS, Mp, ctx=bytes.fromhex(self.domain))
    self.tradsig.verify(tradS, Mp)



class MLDSA44_RSA2048_PSS(CompositeSig):
  id = "id-MLDSA44-RSA2048-PSS"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,60))
  mldsa = MLDSA44()
  tradsig = RSA2048PSS()
  domain = "060B6086480186FA6B5008013C"


class MLDSA44_RSA2048_PKCS15(CompositeSig):
  id = "id-MLDSA44-RSA2048-PKCS15"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,61))
  mldsa = MLDSA44()
  tradsig = RSA2048PKCS15()
  domain = "060B6086480186FA6B5008013D"


class MLDSA44_Ed25519(CompositeSig):
  id = "id-MLDSA44-Ed25519"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,62))
  mldsa = MLDSA44()
  tradsig = Ed25519()
  domain = "060B6086480186FA6B5008013E"


class MLDSA44_ECDSA_P256(CompositeSig):
  id = "id-MLDSA44-ECDSA-P256"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,63))
  mldsa = MLDSA44()
  tradsig = ECDSAP256()
  domain = "060B6086480186FA6B5008013F"


class MLDSA65_RSA3072_PSS(CompositeSig):
  id = "id-MLDSA65-RSA3072-PSS"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,64))
  mldsa = MLDSA65()
  tradsig = RSA3072PSS()
  domain = "060B6086480186FA6B50080140"


class MLDSA65_RSA3072_PKCS15(CompositeSig):
  id = "id-MLDSA65-RSA3072-PKCS15"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,65))
  mldsa = MLDSA65()
  tradsig = RSA3072PKCS15()
  domain = "060B6086480186FA6B50080141"


class MLDSA65_RSA4096_PSS(CompositeSig):
  id = "id-MLDSA65-RSA4096-PSS"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,66))
  mldsa = MLDSA65()
  tradsig = RSA4096PSS()
  domain = "060B6086480186FA6B50080142"


class MLDSA65_RSA4096_PKCS15(CompositeSig):
  id = "id-MLDSA65-RSA4096-PKCS15"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,67))
  mldsa = MLDSA65()
  tradsig = RSA4096PKCS15()
  domain = "060B6086480186FA6B50080143"


class MLDSA65_ECDSA_P256(CompositeSig):
  id = "id-MLDSA65-ECDSA-P256"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,68))
  mldsa = MLDSA65()
  tradsig = ECDSAP256()
  domain = "060B6086480186FA6B50080144"


class MLDSA65_ECDSA_P384(CompositeSig):
  id = "id-MLDSA65-ECDSA-P384"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,69))
  mldsa = MLDSA65()
  tradsig = ECDSAP384()
  domain = "060B6086480186FA6B50080145"


class MLDSA65_ECDSA_brainpoolP256r1(CompositeSig):
  id = "id-MLDSA65-ECDSA-brainpoolP256r1"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,70))
  mldsa = MLDSA65()
  tradsig = ECDSABP256()
  domain = "060B6086480186FA6B50080146"


class MLDSA65_Ed25519(CompositeSig):
  id = "id-MLDSA65-Ed25519"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,71))
  mldsa = MLDSA65()
  tradsig = Ed25519()
  domain = "060B6086480186FA6B50080147"


class MLDSA87_ECDSA_P384(CompositeSig):
  id = "id-MLDSA87-ECDSA-P384"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,72))
  mldsa = MLDSA87()
  tradsig = ECDSAP384()
  domain = "060B6086480186FA6B50080148"


class MLDSA87_ECDSA_brainpoolP384r1(CompositeSig):
  id = "id-MLDSA87-ECDSA-brainpoolP384r1"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,73))
  mldsa = MLDSA87()
  tradsig = ECDSABP384()
  domain = "060B6086480186FA6B50080149"


class MLDSA87_Ed448(CompositeSig):
  id = "id-MLDSA87-Ed448"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,74))
  mldsa = MLDSA87()
  tradsig = Ed448()
  domain = "060B6086480186FA6B5008014A"


class MLDSA87_RSA4096_PSS(CompositeSig):
  id = "id-MLDSA87-RSA4096-PSS"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,75))
  mldsa = MLDSA87()
  tradsig = RSA4096PSS()
  domain = "060B6086480186FA6B5008014B"


class HashMLDSA44_RSA2048_PSS_SHA256(HashCompositeSig):
  id = "id-HashMLDSA44-RSA2048-PSS-SHA256"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,80))
  mldsa = MLDSA44()
  tradsig = RSA2048PSS()
  PH = hashes.SHA256()
  domain = "060B6086480186FA6B50080150"


class HashMLDSA44_RSA2048_PKCS15_SHA256(HashCompositeSig):
  id = "id-HashMLDSA44-RSA2048-PKCS15-SHA256"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,81))
  mldsa = MLDSA44()
  tradsig = RSA2048PKCS15()
  PH = hashes.SHA256()
  domain = "060B6086480186FA6B50080151"


class HashMLDSA44_Ed25519_SHA512(HashCompositeSig):
  id = "id-HashMLDSA44-Ed25519-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,82))
  mldsa = MLDSA44()
  tradsig = Ed25519()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B50080152"


class HashMLDSA44_ECDSA_P256_SHA256(HashCompositeSig):
  id = "id-HashMLDSA44-ECDSA-P256-SHA256"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,83))
  mldsa = MLDSA44()
  tradsig = ECDSAP256()
  PH = hashes.SHA256()
  domain = "060B6086480186FA6B50080153"


class HashMLDSA65_RSA3072_PSS_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-RSA3072-PSS-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,84))
  mldsa = MLDSA65()
  tradsig = RSA3072PSS()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B50080154"


class HashMLDSA65_RSA3072_PKCS15_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-RSA3072-PSS-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,85))
  mldsa = MLDSA65()
  tradsig = RSA3072PKCS15()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B50080155"


class HashMLDSA65_RSA4096_PSS_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-RSA4096-PSS-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,86))
  mldsa = MLDSA65()
  tradsig = RSA4096PSS()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B50080156"


class HashMLDSA65_RSA4096_PKCS15_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-RSA4096-PKCS15-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,87))
  mldsa = MLDSA65()
  tradsig = RSA4096PSS()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B50080157"


class HashMLDSA65_ECDSA_P256_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-ECDSA-P256-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,88))
  mldsa = MLDSA65()
  tradsig = ECDSAP256()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B50080158"


class HashMLDSA65_ECDSA_P384_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-ECDSA-P384-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,89))
  mldsa = MLDSA65()
  tradsig = ECDSAP384()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B50080159"


class HashMLDSA65_ECDSA_brainpoolP256r1_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-ECDSA-brainpoolP256r1-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,90))
  mldsa = MLDSA65()
  tradsig = ECDSABP256()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B5008015A"


class HashMLDSA65_Ed25519_SHA512(HashCompositeSig):
  id = "id-HashMLDSA65-Ed25519-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,91))
  mldsa = MLDSA65()
  tradsig = Ed25519()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B5008015B"


class HashMLDSA87_ECDSA_P384_SHA512(HashCompositeSig):
  id = "id-HashMLDSA87-ECDSA-P384-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,92))
  mldsa = MLDSA87()
  tradsig = ECDSAP384()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B5008015C"


class HashMLDSA87_ECDSA_brainpoolP384r1_SHA512(HashCompositeSig):
  id = "id-HashMLDSA87-ECDSA-brainpoolP384r1-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,93))
  mldsa = MLDSA87()
  tradsig = ECDSABP384()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B5008015D"


class HashMLDSA87_Ed448_SHA512(HashCompositeSig):
  id = "id-HashMLDSA87-Ed448-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,94))
  mldsa = MLDSA87()
  tradsig = Ed448()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B5008015E"


class HashMLDSA87_RSA4096_PSS_SHA512(HashCompositeSig):
  id = "id-HashMLDSA87-RSA4096-PSS-SHA512"
  oid = univ.ObjectIdentifier((2,16,840,1,114027,80,8,1,1,95))
  mldsa = MLDSA87()
  tradsig = RSA4096PSS()
  PH = hashes.SHA512()
  domain = "060B6086480186FA6B5008015F"






### Generate CA Cert and KEM Cert ###

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
  cert_pyasn1, _ = decode(certDer, rfc5280.Certificate())

  # Manually set the algID to ML-DSA-65 and re-sign it
  sigAlgID = rfc5280.AlgorithmIdentifier()
  sigAlgID['algorithm'] = univ.ObjectIdentifier((2,16,840,1,101,3,4,3,18))
  cert_pyasn1['tbsCertificate']['signature'] = sigAlgID
  tbs_bytes = encode(cert_pyasn1['tbsCertificate'])
  cert_pyasn1['signatureAlgorithm'] = sigAlgID
  cert_pyasn1['signature'] = univ.BitString(hexValue=ML_DSA_65.sign(caSK, tbs_bytes).hex())

  return x509.load_der_x509_certificate(encode(cert_pyasn1))


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
  cert_pyasn1, _ = decode(cert_der, rfc5280.Certificate())

  spki = rfc5280.SubjectPublicKeyInfo()
  algid = rfc5280.AlgorithmIdentifier()
  algid['algorithm'] = sig.oid
  if sig.pss_params_asn != None:
    algid['parameters'] = sig.pss_params_asn
  spki['algorithm'] = algid
  spki['subjectPublicKey'] = univ.BitString(hexValue=sig.public_key_bytes().hex())
  cert_pyasn1['tbsCertificate']['subjectPublicKeyInfo'] = spki


  # cert = caSign(cert, sig.sk)

  # Manually set the algID to ML-DSA and re-sign it
  sigAlgID = rfc5280.AlgorithmIdentifier()
  sigAlgID['algorithm'] = sig.oid
  if sig.pss_params_asn != None:
    sigAlgID['parameters'] = sig.pss_params_asn
  cert_pyasn1['tbsCertificate']['signature'] = sigAlgID
  tbs_bytes = encode(cert_pyasn1['tbsCertificate'])
  cert_pyasn1['signatureAlgorithm'] = sigAlgID
  cert_pyasn1['signature'] = univ.BitString(hexValue=sig.sign(tbs_bytes).hex())

  return x509.load_der_x509_certificate(encode(cert_pyasn1))







def formatResults(sig, s ):
  jsonTest = {}
  jsonTest['tcId'] = sig.id
  jsonTest['pk'] = base64.b64encode(sig.public_key_bytes()).decode('ascii')

  cert = signSigCert(sig)
  jsonTest['x5c'] = base64.b64encode(cert.public_bytes(encoding=serialization.Encoding.DER)).decode('ascii')
  jsonTest['sk'] = base64.b64encode(sig.private_key_bytes()).decode('ascii')
  jsonTest['s'] = base64.b64encode(s).decode('ascii')

  return jsonTest

def output_artifacts_certs_r5(jsonTestVectors):

  artifacts_zip = ZipFile('artifacts_certs_r5.zip', mode='w')

  for tc in jsonTestVectors['tests']:
      try:
          # <friendlyname>-<oid>_ta.der
          certFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_ta.der"
          keyFilename = tc['tcId'] + "-" + str(OID_TABLE[tc['tcId']]) + "_priv.raw"
      except KeyError:
          # if this one is not in the OID_TABLE, then just skip it
          continue
      
      artifacts_zip.writestr(certFilename, data=base64.b64decode(tc['x5c']))
      artifacts_zip.writestr(keyFilename, data=base64.b64decode(tc['sk']))


def writeDumpasn1Cfg():
  """
  Creates a dumpasn1.cfg file based on the OID mapping table in this script.
  """

  with open('dumpasn1.cfg', 'w') as f:
    f.write("# dumpasn1 Object Identifier configuration file.")
    f.write("# Generated by the Composite Signatures reference implementation")
    f.write("# available at: https://github.com/lamps-wg/draft-composite-sigs")
    f.write("")

    for oid in OID_TABLE:
      f.write("OID = "+ str(OID_TABLE[oid]).replace('.', ' '))
      f.write("Comment = "+ oid)
      f.write("Description = "+ oid)
      f.write("")


_m = b'The quick brown fox jumps over the lazy dog.'

def doSig(sig, PH=None):
  sig.keyGen()
  s = sig.sign(_m)
  sig.verify(s, _m)

  return formatResults(sig, s)


def main():

  jsonOutput = {}

  jsonOutput['m'] = base64.b64encode(_m).decode('ascii')

  jsonOutput['tests'] = []


  # Single algs - remove these, just for testing
  # jsonOutput['tests'].append( doSig(RSA2048PSS()) )
  # jsonOutput['tests'].append( doSig(RSA2048PKCS1()) )
  # jsonOutput['tests'].append( doSig(RSA3072PSS()) )
  # jsonOutput['tests'].append( doSig(RSA3072PKCS1()) )
  # jsonOutput['tests'].append( doSig(RSA4096PSS()) )
  # jsonOutput['tests'].append( doSig(RSA4096PKCS1()) )
  # jsonOutput['tests'].append( doSig(ECDSAP256()) )
  # jsonOutput['tests'].append( doSig(ECDSABP256()) )
  # jsonOutput['tests'].append( doSig(ECDSAP384()) )
  # jsonOutput['tests'].append( doSig(ECDSABP384()) )
  # jsonOutput['tests'].append( doSig(Ed25519()) )
  # jsonOutput['tests'].append( doSig(Ed448()) )
  jsonOutput['tests'].append( doSig(MLDSA44()) )
  jsonOutput['tests'].append( doSig(MLDSA65()) )
  jsonOutput['tests'].append( doSig(MLDSA87()) )
  
  

  # Composites
  jsonOutput['tests'].append( doSig(MLDSA44_RSA2048_PSS()) )
  jsonOutput['tests'].append( doSig(MLDSA44_RSA2048_PKCS15()) )
  jsonOutput['tests'].append( doSig(MLDSA44_Ed25519()) )
  jsonOutput['tests'].append( doSig(MLDSA44_ECDSA_P256()) )
  jsonOutput['tests'].append( doSig(MLDSA65_RSA3072_PSS()) )
  jsonOutput['tests'].append( doSig(MLDSA65_RSA3072_PKCS15()) )
  jsonOutput['tests'].append( doSig(MLDSA65_RSA4096_PSS()) )
  jsonOutput['tests'].append( doSig(MLDSA65_RSA4096_PKCS15()) )
  jsonOutput['tests'].append( doSig(MLDSA65_ECDSA_P256()) )
  jsonOutput['tests'].append( doSig(MLDSA65_ECDSA_P384()) )
  jsonOutput['tests'].append( doSig(MLDSA65_ECDSA_brainpoolP256r1()) )
  jsonOutput['tests'].append( doSig(MLDSA65_Ed25519()) )
  jsonOutput['tests'].append( doSig(MLDSA87_ECDSA_P384()) )
  jsonOutput['tests'].append( doSig(MLDSA87_ECDSA_brainpoolP384r1()) )
  jsonOutput['tests'].append( doSig(MLDSA87_Ed448()) )
  jsonOutput['tests'].append( doSig(MLDSA87_RSA4096_PSS()) )

  jsonOutput['tests'].append( doSig(HashMLDSA44_RSA2048_PSS_SHA256()) )
  jsonOutput['tests'].append( doSig(HashMLDSA44_RSA2048_PKCS15_SHA256()) )
  jsonOutput['tests'].append( doSig(HashMLDSA44_Ed25519_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA44_ECDSA_P256_SHA256()) )
  jsonOutput['tests'].append( doSig(HashMLDSA65_RSA3072_PSS_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA65_RSA4096_PSS_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA65_RSA4096_PKCS15_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA65_ECDSA_P256_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA65_ECDSA_P384_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA65_ECDSA_brainpoolP256r1_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA65_Ed25519_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA87_ECDSA_P384_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA87_ECDSA_brainpoolP384r1_SHA512()) )
  jsonOutput['tests'].append( doSig(HashMLDSA87_RSA4096_PSS_SHA512()) )

  


  with open('testvectors.json', 'w') as f:
    f.write(json.dumps(jsonOutput, indent=2))
  
  with open('testvectors_wrapped.json', 'w') as f:
    f.write('\n'.join(textwrap.wrap(''.join(json.dumps(jsonOutput, indent="")), 
                                  width=68,
                                  replace_whitespace=False,
                                  drop_whitespace=False)))

  writeDumpasn1Cfg()


main()