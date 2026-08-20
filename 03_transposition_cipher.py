"""
CSE-4232P Cryptography and Network Security Lab
Problem 3: Transposition Cipher

Problem:
Plaintext:
"DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLY UNIVERSITY OF RAJSHAHI BANGLADESH"
Take the width as input, encrypt using a transposition cipher, then
reverse the process to recover the original plaintext.

Method used:
1. Write plaintext row by row using the given width.
2. Read column by column to obtain the ciphertext.
"""

DEFAULT_TEXT = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLY UNIVERSITY OF RAJSHAHI BANGLADESH"
PAD = '~'


def transposition_encrypt(plaintext, width):
    if width <= 0:
        raise ValueError("Width must be greater than 0")

    text = plaintext
    while len(text) % width != 0:
        text += PAD

    rows = len(text) // width
    ciphertext = ""

    for col in range(width):
        for row in range(rows):
            ciphertext += text[row * width + col]

    return ciphertext


def transposition_decrypt(ciphertext, width):
    if width <= 0:
        raise ValueError("Width must be greater than 0")

    rows = len(ciphertext) // width
    grid = [[''] * width for _ in range(rows)]
    index = 0

    for col in range(width):
        for row in range(rows):
            grid[row][col] = ciphertext[index]
            index += 1

    plaintext = ''.join(''.join(row) for row in grid)
    return plaintext.rstrip(PAD)


if __name__ == "__main__":
    print("Default plaintext:")
    print(DEFAULT_TEXT)

    user_text = input("\nPress Enter to use default text, or type your own plaintext: ")
    plaintext = user_text if user_text else DEFAULT_TEXT
    width = int(input("Enter width: "))

    ciphertext = transposition_encrypt(plaintext, width)
    recovered = transposition_decrypt(ciphertext, width)

    print("\nCiphertext:")
    print(ciphertext)
    print("\nDecrypted plaintext:")
    print(recovered)
