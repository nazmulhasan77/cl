"""
CSE-4232P Cryptography and Network Security Lab
Problem 13: PGP Services

Problem:
a) Implement PGP Authentication.
b) Implement PGP Confidentiality for storing data.

This is a SIMPLE EDUCATIONAL simulation using Python standard libraries.
It demonstrates the sequence of operations, not production security.

Authentication:
Message -> SHA-256 -> RSA signature -> attach signature -> compress
-> Base64 -> store. Reverse these steps to verify.

Confidentiality for storing data:
Message -> compress -> derive symmetric key from passphrase -> encrypt
-> Base64 -> store. Reverse the steps to recover the message.
"""

import base64
import hashlib
import json
import zlib
from math import gcd


def egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m


def make_rsa_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537 if 65537 < phi and gcd(65537, phi) == 1 else 17
    while gcd(e, phi) != 1:
        e += 2
    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def xor_crypt(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


# ---------- Part A: Authentication ----------

def store_authenticated_message(message, private_key, filename):
    digest = hashlib.sha256(message.encode('utf-8')).digest()
    digest_number = int.from_bytes(digest, 'big')

    d, n = private_key
    signature = pow(digest_number % n, d, n)

    packet = json.dumps({
        'message': message,
        'signature': signature
    }).encode('utf-8')

    stored_data = base64.b64encode(zlib.compress(packet))
    with open(filename, 'wb') as file:
        file.write(stored_data)


def read_and_verify_authenticated_message(filename, public_key):
    with open(filename, 'rb') as file:
        stored_data = file.read()

    packet = json.loads(
        zlib.decompress(base64.b64decode(stored_data)).decode('utf-8')
    )

    message = packet['message']
    signature = packet['signature']

    digest = hashlib.sha256(message.encode('utf-8')).digest()
    digest_number = int.from_bytes(digest, 'big')

    e, n = public_key
    valid = pow(signature, e, n) == digest_number % n
    return message, valid


# ---------- Part B: Confidentiality for Storage ----------

def derive_key(passphrase):
    return hashlib.sha256(passphrase.encode('utf-8')).digest()


def store_confidential_message(message, passphrase, filename):
    compressed = zlib.compress(message.encode('utf-8'))
    key = derive_key(passphrase)
    encrypted = xor_crypt(compressed, key)

    with open(filename, 'wb') as file:
        file.write(base64.b64encode(encrypted))


def read_confidential_message(passphrase, filename):
    with open(filename, 'rb') as file:
        encrypted = base64.b64decode(file.read())

    key = derive_key(passphrase)
    compressed = xor_crypt(encrypted, key)
    return zlib.decompress(compressed).decode('utf-8')


if __name__ == "__main__":
    public_key, private_key = make_rsa_keys(3557, 2579)

    message = input("Enter message: ")

    print("\n===== A) AUTHENTICATION FOR STORED DATA =====")
    auth_file = "pgp_authenticated_data.txt"
    store_authenticated_message(message, private_key, auth_file)
    recovered, valid = read_and_verify_authenticated_message(auth_file, public_key)
    print("Saved to        :", auth_file)
    print("Recovered       :", recovered)
    print("Signature valid :", valid)

    print("\n===== B) CONFIDENTIALITY FOR STORED DATA =====")
    passphrase = input("Enter a passphrase: ")
    secret_file = "pgp_confidential_data.txt"
    store_confidential_message(message, passphrase, secret_file)
    recovered = read_confidential_message(passphrase, secret_file)
    print("Saved to  :", secret_file)
    print("Recovered :", recovered)
