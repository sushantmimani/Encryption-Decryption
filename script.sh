#!/bin/bash

# Simple test for fcrypt (CS 4740/6740: Network Security)
# Amirali Sanatinia (amirali@ccs.neu.edu)

python fcrypt.py -e rec_public_key.der send_private_key.pem file.txt ct
python fcrypt.py -d rec_private_key.pem send_public_key.der ct file1.txt

if ! diff -q file.txt file1.txt > /dev/null ; then
  echo "FAIL"
  else echo "PASS!"
fi

