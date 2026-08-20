"""
CSE-4232P Cryptography and Network Security Lab
Problem 12: PGP Services

Problem:
a) Implement PGP Authentication.
b) Implement PGP Confidentiality for transmitting data.

This is a SIMPLE EDUCATIONAL simulation of the PGP steps using only
Python standard libraries. It is NOT production-grade cryptography.

Authentication flow:
Message -> SHA-256 hash -> RSA signature -> attach signature -> compress
-> Base64. Receiver reverses the steps and verifies the signature.

Confidentiality for transmission flow:
Message -> compress -> random session key -> symmetric encryption
-> RSA encrypt session key with receiver public key -> Base64.
Receiver reverses the steps.
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


# ---------- Part A: Authentication ----------

def pgp_authentication_send(message, sender_private_key):
    message_bytes = message.encode('utf-8')
    digest = hashlib.sha256(message_bytes).digest()
    digest_number = int.from_bytes(digest, 'big')

    d, n = sender_private_key
    signature = pow(digest_number % n, d, n)

    packet = {
        'message': message,
        'signature': signature
    }
    packed = json.dumps(packet).encode('utf-8')
    compressed = zlib.compress(packed)
    radix64 = base64.b64encode(compressed).decode('ascii')
    return radix64


def pgp_authentication_receive(radix64, sender_public_key):
    compressed = base64.b64decode(radix64)
    packed = zlib.decompress(compressed)
    packet = json.loads(packed.decode('utf-8'))

    message = packet['message']
    signature = packet['signature']

    digest = hashlib.sha256(message.encode('utf-8')).digest()
    digest_number = int.from_bytes(digest, 'big')

    e, n = sender_public_key
    recovered_hash = pow(signature, e, n)
    valid = recovered_hash == digest_number % n
    return message, valid


# ---------- Part B: Confidentiality for Transmission ----------

def pgp_confidentiality_send(message, receiver_public_key):
    compressed = zlib.compress(message.encode('utf-8'))

    # Random 16-byte one-time session key for this message.
    session_key = secrets.token_bytes(16)
    encrypted_data = xor_crypt(compressed, session_key)

    encrypted_session_key = rsa_encrypt_bytes(session_key, receiver_public_key)

    packet = {
        'encrypted_session_key': encrypted_session_key,
        'encrypted_data': base64.b64encode(encrypted_data).decode('ascii')
    }

    return base64.b64encode(json.dumps(packet).encode('utf-8')).decode('ascii')


def pgp_confidentiality_receive(radix64, receiver_private_key):
    packet_json = base64.b64decode(radix64)
    packet = json.loads(packet_json.decode('utf-8'))

    session_key = rsa_decrypt_bytes(
        packet['encrypted_session_key'], receiver_private_key
    )
    encrypted_data = base64.b64decode(packet['encrypted_data'])
    compressed = xor_crypt(encrypted_data, session_key)
    message = zlib.decompress(compressed).decode('utf-8')
    return message


if __name__ == "__main__":
    # Fixed small RSA examples for easy lab demonstration.
    sender_public, sender_private = make_rsa_keys(3557, 2579)
    receiver_public, receiver_private = make_rsa_keys(3673, 3253)

    message = input("Enter message: ")

    print("\n===== A) PGP AUTHENTICATION =====")
    auth_packet = pgp_authentication_send(message, sender_private)
    print("Transmitted authentication packet:")
    print(auth_packet)

    auth_message, valid = pgp_authentication_receive(auth_packet, sender_public)
    print("Recovered message:", auth_message)
    print("Signature valid  :", valid)

    print("\n===== B) PGP CONFIDENTIALITY FOR TRANSMISSION =====")
    secret_packet = pgp_confidentiality_send(message, receiver_public)
    print("Transmitted confidential packet:")
    print(secret_packet)

    recovered = pgp_confidentiality_receive(secret_packet, receiver_private)
    print("Recovered message:", recovered)
