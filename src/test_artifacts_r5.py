#!/usr/bin/env python3

import sys, os, re
from glob import glob
import zipfile, tempfile

from pyasn1.type import univ

import generate_test_vectors

if len(sys.argv) < 3:
    exit("Please call this as `test_artifacts_r5.py [provider] [artifacts_certs_r5.zip]`")

prov = sys.argv[1]

infile = sys.argv[2]
if infile is None:
  exit("Input file is required.")

print("\n\nTesting "+prov+" / "+infile+" against "+generate_test_vectors.VERSION_IMPLEMENTED)


os.makedirs("output/certs/compatMatrices/artifacts_certs_r5", exist_ok=True)

compatMatrixFile = open("output/certs/compatMatrices/artifacts_certs_r5/"+prov+"_composite-ref-impl.csv", 'w')
compatMatrixFile.write("key_algorithm_oid,type,test_result\n")


zipf = zipfile.ZipFile(infile)

tmpdir = tempfile.mkdtemp()
zipf.extractall(tmpdir)


# Extract the artifacts zip
# do a recursive search to be robust to extra layers of folders in the zip
for filename in glob(tmpdir+'/**/*_ta.der', recursive=True):

  # check if the OID in the file name is a supported composite
  try:
    OID = re.search(r'.*-(([0-9]+\.?)*)_.*', filename).groups()[0]
  except:
    print("Could not parse this file name, skipping. "+filename)
    continue

  # if not univ.ObjectIdentifier(OID) in generate_test_vectors.OID_TABLE.values():
  OIDname = [key for key, val in generate_test_vectors.OID_TABLE.items() if val == univ.ObjectIdentifier(OID)]

  if OIDname == []:
    print("DEBUG: OID does not represent a composite (at least not of this version of the draft): "+OID)
    continue
  OIDname = OIDname[0]
  

  fullFileName = os.path.join(tmpdir, filename) 
  print("\nProcessing "+OIDname+" from "+fullFileName)
  with open(fullFileName, "rb") as f:
    try:
      certbytes = f.read()
      res = generate_test_vectors.verifyCert(certbytes)
      print("\tCert passed verification: "+str(res))
      if res:
        compatMatrixFile.write(OID+",cert,Y\n")
      else:
        compatMatrixFile.write(OID+",cert,N\n")
    except LookupError as e:
      print("Certificate is not signed with a composite (at least not of this version of the draft)")
      print(e)

