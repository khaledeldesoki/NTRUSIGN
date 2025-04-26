#! /bin/python

import sys
import NTRU
import KeyGenerator
from time import time

if len(sys.argv) == 1:
    print("No arguments were provided !\n")
    exit(1)
#use this numbers for testing
# (N, q, df, dg, B, t, N_bound) = (7, 13, 2, 2, 1, 'transpose', 17)
(N, q, df, dg, B, t, N_bound) = (251, 128, 73, 71, 1, 'transpose', 545)
k = KeyGenerator.KeyPair()
i = 1
while i < len(sys.argv):
    if sys.argv[i] == '-ip':
        i += 1
        path = sys.argv[i]
        infile = open(path, 'r')
        key_pub_str = infile.read()
        k.import_pub(key_pub_str)

    elif sys.argv[i] == '-is':
        i += 1
        path = sys.argv[i]
        infile = open(path, 'r')
        key_priv_str = infile.read()
        k.import_priv(key_priv_str)

    elif sys.argv[i] == '-s':
        if k.priv is None:
            print("No private key imported !")
            exit(1)

        i += 1
        path = sys.argv[i]
        infile = open(path, 'rb')
        doc_to_sign = infile.read()

        t = time()
        (D, r, s) = NTRU.Signing(k, doc_to_sign, N_bound)
        sig = NTRU.export_signature(r, s, N_bound, False)
        print(f"\nDocument signed in {int(100*(time()-t))/100}s")

        name = path.split('/')
        name[-1] += ".ntru"
        path = "/".join(name)

        outfile = open(path, 'w')
        outfile.write(sig)
        outfile.close()

    elif sys.argv[i] == "-v":
        if k.pub is None and k.priv is None:
            print("No key to verify the signature")
            exit(1)

        i += 1
        path = sys.argv[i]
        infile = open(path, 'rb')
        doc_to_verify = infile.read()

        infile = open(path+".ntru", 'r')
        signature_str = infile.read()
        r, s = NTRU.import_signature(signature_str)

        verif = NTRU.Verifying(doc_to_verify, r, s, N_bound, k)
        if verif:
            print(f"This document has been signed by {k.name} ({k.email})")
        else:
            print("Wrong signature :(")

    elif sys.argv[i] == "-g":
        i += 1
        filename = sys.argv[i]

        name = input("What's your name ? ")
        email = input("What's your email address ? ")

        t = time()
        k = KeyGenerator.KeyPair(gen=True, name=name, email=email)
        s_pub = k.export_pub(False)
        s_priv = k.export_priv(False)
        outfile = open(filename+"_pub.asc", "w")
        outfile.write(s_pub)
        outfile.close()

        outfile = open(filename+"_priv.asc", "w")
        outfile.write(s_priv)
        outfile.close()

        print(f'Keys generated as {filename} in {int(100*(time()-t))/100}')

    else:
        exit(1)
    i += 1
