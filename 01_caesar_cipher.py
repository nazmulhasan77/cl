"""
CSE-4232P Cryptography and Network Security Lab
Problem 1: Caesar Cipher

Problem:
Given a line of plaintext, find the Caesar Cipher by shifting every
alphabetic character 3 positions to the right modulo 26.
Then decrypt the ciphertext to recover the original plaintext.
"""


def caesar_encrypt(text, shift=3):
    result = ""
    for ch in text:
        if 'A' <= ch <= 'Z':
            result += chr((ord(ch) - ord('A') + shift) % 26 + ord('A'))
        elif 'a' <= ch <= 'z':
            result += chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
        else:
            result += ch
    return result


def caesar_decrypt(text, shift=3):
    return caesar_encrypt(text, -shift)


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    ciphertext = caesar_encrypt(plaintext)
    recovered = caesar_decrypt(ciphertext)

    print("\nCiphertext :", ciphertext)
    print("Decrypted  :", recovered)
