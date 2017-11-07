To encrypt the plaintext, on terminal run as:

fcrypt.py -e destination_public_key.der sender_private_key.der file_to_encrypt cipherText

To decrypt the ciphertext, on terminal run as:

python fcrypt.py -d sender_public_key.der destination_private_key.der cipherText file_for_plainText

The program uses the encryption technique as documented on the PGP wiki page (https://en.wikipedia.org/wiki/Pretty_Good_Privacy). The text is encrypted using symmetric encrytion and then this key is encrypted using the receiver's public RSA key
