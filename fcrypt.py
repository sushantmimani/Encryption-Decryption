import os
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization




def encrypt(key, iv, destination_public_key_filename, sender_private_key_filename, message):
    print("Calling encryption")
    # Read the receiver's public key
    try:
        with open(destination_public_key_filename, "rb") as key_file:
            recv_public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except ValueError:
        with open(destination_public_key_filename, "rb") as key_file:
            recv_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

    # Read senders's private key
    try:
        with open(sender_private_key_filename, "rb") as key_file:
            send_private_key = serialization.load_der_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except ValueError:
        with open(sender_private_key_filename, "rb") as key_file:
            send_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )


    # Encrypt data using random key
    encrypt_cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = encrypt_cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()

    # Sign the cipher text using sender's private key
    signature = send_private_key.sign(
        ct,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Encrypt random key using receiver's public key
    encrypted_key = recv_public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ct, encrypted_key, signature, encryptor.tag


def decrypt(destination_private_key_filename, sender_public_key_filename, cipherText):
    print("Calling decryption")

    message, key, iv, tag, signature = cipherText.split('***SEGMENTEND***')

    # Read receivers's private key
    try:
        with open(destination_private_key_filename, "rb") as key_file:
            recv_private_key = serialization.load_der_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except ValueError:
        with open(destination_private_key_filename, "rb") as key_file:
            recv_private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

    # Read the senders's public key
    try:
        with open(sender_public_key_filename, "rb") as key_file:
            send_public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend()
            )
    except ValueError:
        with open(sender_public_key_filename, "rb") as key_file:
            send_public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

    try:
        signature = send_public_key.verify(signature,
                                           message, padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
                                           hashes.SHA256()
                                           )
        print("Signature Verified")
    except:
        print("Signature couldn't be verified")
        return "FAIL"

    # Decrypt random key using private key
    decrypted_key = recv_private_key.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    decrypt_cipher = Cipher(algorithms.AES(decrypted_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = decrypt_cipher.decryptor()

    plainText = decryptor.update(message) + decryptor.finalize()

    return plainText


if __name__ == '__main__':
    if len(sys.argv) != 6:
        print("Incorrect arguments")

    elif sys.argv[1] == '-e':
        key = os.urandom(32)
        iv = os.urandom(96)
        destination_public_key_filename = sys.argv[2]  # Read receiver's public key
        sender_private_key_filename = sys.argv[3]  # Read sender's private key
        file_pt = open(sys.argv[4], "r")
        plainText = file_pt.read()  # Read the plain text
        file_pt.close()
        cipherText, encryptedKey, signature, tag = encrypt(key, iv, destination_public_key_filename,
                                                           sender_private_key_filename, plainText)

        # Add all items required for successfull decrytion to the cipherText file
        file_ct = open(sys.argv[5], 'w+')
        file_ct.write(cipherText)
        file_ct.write("***SEGMENTEND***")
        file_ct.write(encryptedKey)
        file_ct.write("***SEGMENTEND***")
        file_ct.write(iv)
        file_ct.write("***SEGMENTEND***")
        file_ct.write(tag)
        file_ct.write("***SEGMENTEND***")
        file_ct.write(signature)
        file_ct.close()

    elif sys.argv[1] == '-d':
        destination_private_key_filename = sys.argv[2]
        sender_public_key_filename = sys.argv[3]
        file_ct = open(sys.argv[4], "r")
        cipherText = file_ct.read()
        decryptText = decrypt(destination_private_key_filename, sender_public_key_filename, cipherText)
        file_pt = open(sys.argv[5], 'w+')
        file_pt.write(decryptText)
        file_pt.close()
