#!/usr/bin/env python3

import sys
import re

from pyasn1.type import univ

import generate_test_vectors

if len(sys.argv) < 2:
    exit("Input file is required.")

infile = sys.argv[1]
if infile is None:
  exit("Input file is required.")

print("Testing "+infile+" against "+generate_test_vectors.VERSION_IMPLEMENTED)

OID = re.search(r'.*-(([0-9]+\.?)*)_.*', infile).groups()[0]

# if not univ.ObjectIdentifier(OID) in generate_test_vectors.OID_TABLE.values():
OIDname = [key for key, val in generate_test_vectors.OID_TABLE.items() if val == univ.ObjectIdentifier(OID)]

if OIDname == []:
   exit("OID does not represent a composite (at least not of this version of the draft): "+OID)
OIDname = OIDname[0]


with open(infile, "rb") as f:
  try:
    res = generate_test_vectors.verifyCert(f.read())
    print("Result: "+str(res))
  except LookupError:
     print("Certificate is not signed with a composite (at least not of this version of the draft)")
  except ValueError:
     print("Error: Input could not be parsed as a DER or PEM certificate: "+infile)