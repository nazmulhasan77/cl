"""
CSE-4232P Cryptography and Network Security Lab
Problem 9: Secured Hash Algorithm (SHA) One-Way Hash Function

Problem:
Write a program to implement SHA one-way hash function.

This lab solution uses SHA-1 because many classical cryptography lab
syllabi refer to SHA-1 simply as SHA. SHA-1 produces a 160-bit hash.
For real modern applications, SHA-256 or stronger should be preferred.
"""

import hashlib


def sha1_hash(message):
    data = message.encode('utf-8')
    return hashlib.sha1(data).hexdigest()


if __name__ == "__main__":
    message = input("Enter message: ")
    digest = sha1_hash(message)

    print("\nSHA-1 hash:")
    print(digest)
