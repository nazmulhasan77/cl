"""
CSE-4232P Cryptography and Network Security Lab
Problem 2: Polygram Substitution Cipher (Block size = 3)

Problem:
Find the Polygram Substitution Cipher of a given plaintext using blocks
of 3 characters. Then decrypt it to recover the plaintext.

This solution uses the Hill Cipher, a standard polygram substitution
cipher. A 3x3 key matrix is used because the block size is 3.
"""

KEY = [
    [6, 24, 1],
    [13, 16, 10],
    [20, 17, 15]
]

# Inverse of KEY modulo 26
INV_KEY = [
    [8, 5, 10],
    [21, 8, 21],
    [21, 12, 8]
]


def clean_text(text):
    return ''.join(ch for ch in text.upper() if ch.isalpha())


def matrix_vector_multiply(matrix, vector):
    result = []
    for row in matrix:
        value = sum(row[i] * vector[i] for i in range(3)) % 26
        result.append(value)
    return result


def hill_encrypt(plaintext):
    text = clean_text(plaintext)
    while len(text) % 3 != 0:
        text += 'X'

    ciphertext = ""
    for i in range(0, len(text), 3):
        block = [ord(ch) - ord('A') for ch in text[i:i+3]]
        encrypted = matrix_vector_multiply(KEY, block)
        ciphertext += ''.join(chr(x + ord('A')) for x in encrypted)
    return ciphertext


def hill_decrypt(ciphertext):
    text = clean_text(ciphertext)
    plaintext = ""
    for i in range(0, len(text), 3):
        block = [ord(ch) - ord('A') for ch in text[i:i+3]]
        decrypted = matrix_vector_multiply(INV_KEY, block)
        plaintext += ''.join(chr(x + ord('A')) for x in decrypted)
    return plaintext


if __name__ == "__main__":
    plaintext = input("Enter plaintext: ")
    ciphertext = hill_encrypt(plaintext)
    recovered = hill_decrypt(ciphertext)

    print("\nCiphertext        :", ciphertext)
    print("Decrypted text    :", recovered)
    print("Note: trailing X may be padding.")
