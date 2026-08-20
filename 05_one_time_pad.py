"""
CSE-4232P Cryptography and Network Security Lab
Problem 5: One Time Pad (OTP)

Problem:
A file contains a large set of truly random key letters. Encrypt a
plaintext using the One Time Pad technique. Then decrypt the ciphertext
to recover the original plaintext.

Important OTP rules:
1. Key must be truly random.
2. Key must be at least as long as the plaintext letters being encrypted.
3. The same key portion must NEVER be reused.

This program reads key letters from a file.
"""


def read_key_letters(filename):
    with open(filename, 'r', encoding='utf-8') as file:
        data = file.read().upper()
    return ''.join(ch for ch in data if 'A' <= ch <= 'Z')


def otp_encrypt(plaintext, key_letters):
    result = ""
    key_index = 0

    for ch in plaintext:
        if ch.isalpha() and ch.isascii():
            if key_index >= len(key_letters):
                raise ValueError("Key file does not contain enough key letters")

            base = ord('A') if ch.isupper() else ord('a')
            p = ord(ch.upper()) - ord('A')
            k = ord(key_letters[key_index]) - ord('A')
            c = (p + k) % 26
            result += chr(c + base)
            key_index += 1
        else:
            result += ch

    return result, key_index


def otp_decrypt(ciphertext, key_letters):
    result = ""
    key_index = 0

    for ch in ciphertext:
        if ch.isalpha() and ch.isascii():
            if key_index >= len(key_letters):
                raise ValueError("Key file does not contain enough key letters")

            base = ord('A') if ch.isupper() else ord('a')
            c = ord(ch.upper()) - ord('A')
            k = ord(key_letters[key_index]) - ord('A')
            p = (c - k) % 26
            result += chr(p + base)
            key_index += 1
        else:
            result += ch

    return result


if __name__ == "__main__":
    key_file = input("Enter random key file path: ").strip()
    key_letters = read_key_letters(key_file)

    plaintext = input("Enter plaintext: ")
    ciphertext, used = otp_encrypt(plaintext, key_letters)
    recovered = otp_decrypt(ciphertext, key_letters[:used])

    print("\nCiphertext :", ciphertext)
    print("Decrypted  :", recovered)
    print("Key letters used:", used)
