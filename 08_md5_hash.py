"""
CSE-4232P Cryptography and Network Security Lab
Problem 8: MD5 One-Way Hash Function

Problem:
Write a program to implement the MD5 one-way hash function.

This simple lab implementation uses Python's standard hashlib module.
MD5 produces a 128-bit hash, usually displayed as 32 hexadecimal digits.
Note: MD5 is cryptographically broken and should not be used for modern
security, but it is included here for educational/lab purposes.
"""

import hashlib


def md5_hash(message):
    data = message.encode('utf-8')
    return hashlib.md5(data).hexdigest()


if __name__ == "__main__":
    message = input("Enter message: ")
    digest = md5_hash(message)

    print("\nMD5 hash:")
    print(digest)
