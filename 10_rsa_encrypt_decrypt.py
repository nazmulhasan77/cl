"""
CSE-4232P Cryptography and Network Security Lab
Problem 10: RSA Encryption and Decryption

Problem:
Encrypt a plaintext message using RSA. Then decrypt the ciphertext to
recover the original plaintext.

Educational RSA steps:
1. Choose two prime numbers p and q.
2. n = p * q
3. phi = (p - 1) * (q - 1)
4. Choose e such that gcd(e, phi) = 1
5. Compute d = e^(-1) mod phi
6. Public key = (e, n), Private key = (d, n)
7. Encrypt: C = M^e mod n
8. Decrypt: M = C^d mod n
"""

from math import gcd


def extended_gcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modular_inverse(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


def choose_e(phi):
    preferred = 65537
    if preferred < phi and gcd(preferred, phi) == 1:
        return preferred

    e = 3
    while e < phi:
        if gcd(e, phi) == 1:
            return e
        e += 2
    raise ValueError("Could not find valid e")


def generate_keys(p, q):
    n = p * q
    if n <= 255:
        raise ValueError("Choose larger primes so that p*q > 255")

    phi = (p - 1) * (q - 1)
    e = choose_e(phi)
    d = modular_inverse(e, phi)
    return (e, n), (d, n)


def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    data = plaintext.encode('utf-8')
    return [pow(byte, e, n) for byte in data]


def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    data = bytes(pow(value, d, n) for value in ciphertext)
    return data.decode('utf-8')


if __name__ == "__main__":
    p = int(input("Enter prime p (example 61): "))
    q = int(input("Enter prime q (example 53): "))

    public_key, private_key = generate_keys(p, q)

    print("\nPublic key :", public_key)
    print("Private key:", private_key)

    plaintext = input("\nEnter plaintext: ")
    ciphertext = rsa_encrypt(plaintext, public_key)
    recovered = rsa_decrypt(ciphertext, private_key)

    print("\nCiphertext numbers:")
    print(ciphertext)
    print("\nDecrypted plaintext:")
    print(recovered)
