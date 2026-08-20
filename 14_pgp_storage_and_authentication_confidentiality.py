"""
CSE-4232P Cryptography and Network Security Lab
Problem 14: PGP Services

Problem:
a) Implement Confidentiality for storing data.
b) Implement Authentication and Confidentiality together.

This is a SIMPLE EDUCATIONAL PGP simulation using Python standard
libraries. It demonstrates the algorithmic flow only.

A) Storage confidentiality:
Message -> compress -> derive key from passphrase -> symmetric encrypt
-> Base64 -> store -> reverse to decrypt.

B) Authentication + Confidentiality for transmission:
Message -> hash -> RSA sign -> attach signature -> compress -> generate
random session key -> symmetric encrypt -> RSA encrypt session key with
receiver public key -> Base64 -> transmit. Receiver reverses all steps
and verifies the sender's signature.
"""

import base64
import hashlib
import json
import secrets
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


def rsa_encrypt_bytes(data, public_key):
    e, n = public_key
    if n <= 255:
        raise ValueError("RSA modulus must be greater than 255")
    return [pow(b, e, n) for b in data]


def rsa_decrypt_bytes(values, private_key):
    d, n = private_key
    return bytes(pow(v, d, n) for v in values)


def xor_crypt(data, key):
    return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))


def derive_key(passphrase):
    return hashlib.sha256(passphrase.encode('utf-8')).digest()


# ---------- Part A: Confidentiality for Storage ----------

def store_confidential(message, passphrase, filename):
    compressed = zlib.compress(message.encode('utf-8'))
    key = derive_key(passphrase)
    encrypted = xor_crypt(compressed, key)

    with open(filename, 'wb') as file:
        file.write(base64.b64encode(encrypted))


def load_confidential(passphrase, filename):
    with open(filename, 'rb') as file:
        encrypted = base64.b64decode(file.read())

    key = derive_key(passphrase)
    compressed = xor_crypt(encrypted, key)
    return zlib.decompress(compressed).decode('utf-8')


# ---------- Part B: Authentication + Confidentiality ----------

def pgp_send_secure(message, sender_private_key, receiver_public_key):
    # 1. Hash message.
    digest = hashlib.sha256(message.encode('utf-8')).digest()
    digest_number = int.from_bytes(digest, 'big')

    # 2. Sign hash using sender private RSA key.
    d, sender_n = sender_private_key
    signature = pow(digest_number % sender_n, d, sender_n)

    # 3. Attach signature to message.
    signed_packet = json.dumps({
        'message': message,
        'signature': signature
    }).encode('utf-8')

    # 4. Compress.
    compressed = zlib.compress(signed_packet)

    # 5. Generate random session key and encrypt compressed data.
    session_key = secrets.token_bytes(16)
    encrypted_data = xor_crypt(compressed, session_key)

    # 6. Encrypt session key with receiver public RSA key.
    encrypted_session_key = rsa_encrypt_bytes(session_key, receiver_public_key)

    # 7. Build packet and apply Radix-64 (Base64).
    outer_packet = {
        'encrypted_session_key': encrypted_session_key,
        'encrypted_data': base64.b64encode(encrypted_data).decode('ascii')
    }

    return base64.b64encode(
        json.dumps(outer_packet).encode('utf-8')
    ).decode('ascii')


def pgp_receive_secure(radix64, receiver_private_key, sender_public_key):
    # 1. Undo Base64 and read packet.
    outer_packet = json.loads(
        base64.b64decode(radix64).decode('utf-8')
    )

    # 2. Recover session key using receiver private RSA key.
    session_key = rsa_decrypt_bytes(
        outer_packet['encrypted_session_key'], receiver_private_key
    )

    # 3. Symmetric decrypt.
    encrypted_data = base64.b64decode(outer_packet['encrypted_data'])
    compressed = xor_crypt(encrypted_data, session_key)

    # 4. Decompress and separate message/signature.
    signed_packet = json.loads(zlib.decompress(compressed).decode('utf-8'))
    message = signed_packet['message']
    signature = signed_packet['signature']

    # 5. Verify sender signature.
    digest = hashlib.sha256(message.encode('utf-8')).digest()
    digest_number = int.from_bytes(digest, 'big')

    e, sender_n = sender_public_key
    recovered_hash = pow(signature, e, sender_n)
    valid = recovered_hash == digest_number % sender_n

    return message, valid


if __name__ == "__main__":
    sender_public, sender_private = make_rsa_keys(3557, 2579)
    receiver_public, receiver_private = make_rsa_keys(3673, 3253)

    message = input("Enter message: ")

    print("\n===== A) CONFIDENTIALITY FOR STORAGE =====")
    passphrase = input("Enter storage passphrase: ")
    filename = "pgp_secure_storage.txt"
    store_confidential(message, passphrase, filename)
    recovered = load_confidential(passphrase, filename)
    print("Saved to  :", filename)
    print("Recovered :", recovered)

    print("\n===== B) AUTHENTICATION + CONFIDENTIALITY =====")
    transmitted = pgp_send_secure(message, sender_private, receiver_public)
    print("Secure transmitted packet:")
    print(transmitted)

    recovered, valid = pgp_receive_secure(
        transmitted, receiver_private, sender_public
    )
    print("Recovered message:", recovered)
    print("Signature valid  :", valid)
