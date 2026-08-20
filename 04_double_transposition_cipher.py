"""
CSE-4232P Cryptography and Network Security Lab
Problem 4: Double Transposition Cipher

Problem:
Find the double Transposition Cipher of the plaintext from Problem 3.
Then decrypt it to recover the original plaintext.

Method used:
Double Columnar Transposition.
- Encrypt once using key 1.
- Encrypt the result again using key 2.
- Decrypt in reverse order: key 2 first, then key 1.
"""

DEFAULT_TEXT = "DEPARTMENT OF COMPUTER SCIENCE AND TECHNOLY UNIVERSITY OF RAJSHAHI BANGLADESH"
PAD = '~'


def column_order(key):
    # Returns column indices in alphabetical order of key letters.
    # The index is included so repeated letters are handled consistently.
    return sorted(range(len(key)), key=lambda i: (key[i], i))


def columnar_encrypt(plaintext, key):
    if not key:
        raise ValueError("Key cannot be empty")

    cols = len(key)
    text = plaintext
    while len(text) % cols != 0:
        text += PAD

    rows = len(text) // cols
    grid = [text[i:i+cols] for i in range(0, len(text), cols)]

    ciphertext = ""
    for col in column_order(key):
        for row in range(rows):
            ciphertext += grid[row][col]

    return ciphertext


def columnar_decrypt(ciphertext, key):
    if not key:
        raise ValueError("Key cannot be empty")
    if len(ciphertext) % len(key) != 0:
        raise ValueError("Ciphertext length must be divisible by key length")

    cols = len(key)
    rows = len(ciphertext) // cols
    grid = [[''] * cols for _ in range(rows)]
    index = 0

    for col in column_order(key):
        for row in range(rows):
            grid[row][col] = ciphertext[index]
            index += 1

    return ''.join(''.join(row) for row in grid)


def double_encrypt(plaintext, key1, key2):
    first = columnar_encrypt(plaintext, key1)
    second = columnar_encrypt(first, key2)
    return second


def double_decrypt(ciphertext, key1, key2):
    first_ciphertext = columnar_decrypt(ciphertext, key2).rstrip(PAD)
    plaintext = columnar_decrypt(first_ciphertext, key1).rstrip(PAD)
    return plaintext


if __name__ == "__main__":
    print("Default plaintext:")
    print(DEFAULT_TEXT)

    user_text = input("\nPress Enter to use default text, or type your own plaintext: ")
    plaintext = user_text if user_text else DEFAULT_TEXT

    key1 = input("Enter first key (example ZEBRA): ").strip().upper()
    key2 = input("Enter second key (example CIPHER): ").strip().upper()

    ciphertext = double_encrypt(plaintext, key1, key2)
    recovered = double_decrypt(ciphertext, key1, key2)

    print("\nDouble Transposition Ciphertext:")
    print(ciphertext)
    print("\nDecrypted plaintext:")
    print(recovered)
