"""
CSE-4232P Cryptography and Network Security Lab
Problem 11: Diffie-Hellman Key Exchange

Problem:
Write a program to implement Diffie-Hellman Key Exchange.

Steps:
1. Publicly choose prime p and primitive root/base g.
2. Alice chooses private key a and computes A = g^a mod p.
3. Bob chooses private key b and computes B = g^b mod p.
4. Alice computes shared key K = B^a mod p.
5. Bob computes shared key K = A^b mod p.
Both shared keys must be equal.
"""


def diffie_hellman(p, g, alice_private, bob_private):
    alice_public = pow(g, alice_private, p)
    bob_public = pow(g, bob_private, p)

    alice_shared = pow(bob_public, alice_private, p)
    bob_shared = pow(alice_public, bob_private, p)

    return alice_public, bob_public, alice_shared, bob_shared


if __name__ == "__main__":
    p = int(input("Enter public prime p (example 23): "))
    g = int(input("Enter public base g (example 5): "))
    a = int(input("Enter Alice private key: "))
    b = int(input("Enter Bob private key: "))

    A, B, key1, key2 = diffie_hellman(p, g, a, b)

    print("\nAlice public key A =", A)
    print("Bob public key B   =", B)
    print("Alice shared key   =", key1)
    print("Bob shared key     =", key2)

    if key1 == key2:
        print("Success: Both parties generated the same shared key.")
    else:
        print("Error: Shared keys are different.")
