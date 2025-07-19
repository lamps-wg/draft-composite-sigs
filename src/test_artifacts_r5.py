#!/usr/bin/env python3

import sys, os, re
import zipfile, tempfile

from pyasn1.type import univ

import generate_test_vectors

if len(sys.argv) < 2:
    exit("Input file is required.")

infile = sys.argv[1]
if infile is None:
  exit("Input file is required.")

print("Testing "+infile+" against "+generate_test_vectors.VERSION_IMPLEMENTED)


zipf = zipfile.ZipFile(infile)

tmpdir = tempfile.mkdtemp()
zipf.extractall(tmpdir)


# TODO -- do a recursive search to handle extra layers of folders

# Extract the artifacts zip
for file in os.listdir(tmpdir):
    filename = os.fsdecode(file)
    if filename.endswith("_ta.der"): 
      # check if the OID in the file name is a supported composite
      OID = re.search(r'.*-(([0-9]+\.?)*)_.*', filename).groups()[0]

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
          # TODO -- output test_results.csv
        except LookupError as e:
          print("Certificate is not signed with a composite (at least not of this version of the draft)")
          print(e)
          # TODO -- output test_results.csv
           
    else:
        continue





