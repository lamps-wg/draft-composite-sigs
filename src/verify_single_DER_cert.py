#!/usr/bin/env python3

import sys
import generate_test_vectors

infile = sys.argv[1]
if infile is None:
    exit("Input file is required.")

with open(infile, "rb") as f:
    try:
        certbytes = f.read()
        res = generate_test_vectors.verifyCert(certbytes)
        print("\tCert passed verification: " + str(res))
    except LookupError as e:
        print(
            "Certificate is not signed with a composite (at least not of this version of the draft)"
        )
        print(e)
