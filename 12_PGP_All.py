import hashlib
import zlib
import math

def generate_key(p = 23, q = 17):
    n = p * q
    phi = (p - 1)*(q-1)

    e = 2

    while math.gcd(e,phi)!=1:
        e+=1
    d = pow(e, -1, phi)
    private_key,public_key = (d,n),(e,n)
    return private_key, public_key

def hash1(text):
    encoded = text.encode()
    h = hashlib.sha256(encoded)
    return h.hexdigest()

def encryption(key, message):
    e, n = key
    cipher_text = []
    for ch in (message):
        m = ord(ch)
        c = pow(m, e, n)
        cipher_text.append(c)
    return cipher_text

def decryption(key, cipher_text):
    d, n = key
    plain_text = ""
    for ch in cipher_text:
        m = chr(pow(ch,d,n))
        plain_text += m

    return plain_text

def sym_encryption(data, key):
    cipher = []
    for byte in data:
        cipher.append(byte^key)
    return bytes(cipher)

def sym_decryption(cipher, key):
    plain = []
    for byte in cipher:
        plain.append(byte^key)

    return bytes(plain)
        

if __name__ == "__main__":
    private_keyA, public_keyA = generate_key()
    private_keyB, public_keyB = generate_key()

    k = 123

    original_message = "The name of my country is Bangladesh"

    h = hash1(original_message)
    ep = encryption(private_keyA, h)
    concate = str(ep) +"|" + original_message
    z = zlib.compress(concate.encode())

    ec = sym_encryption(z,k)
    ep = encryption(public_keyB, str(k))
    concate2 = str(ec) +"|"+str(ep)

    decrypted_compressed_msg, decrypted_pk = concate2.split("|")
    decrypted_pk = eval(decrypted_pk)
    decrypted_compressed_msg = eval(decrypted_compressed_msg)

    dp = decryption(private_keyB, decrypted_pk)
    dc = sym_decryption(decrypted_compressed_msg,int(dp))

    m = zlib.decompress(dc)
    m = m.decode()

    encrypted_signeture, msg = m.split("|")
    decrypted_signature = decryption(public_keyA, eval(encrypted_signeture))
    hashed_msg = hash1(msg)

    print(f"Signature is {decrypted_signature}")
    print(f"Hash of msg is {hashed_msg}")
    if (decrypted_signature == hashed_msg):
        print("pgp successful")
    else:
        print ("Error")









import hashlib
import zlib
import math


# Generate RSA public and private key pair
def generate_key(p=23, q=17):
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 2

    # Find e such that gcd(e, phi) = 1
    while math.gcd(e, phi) != 1:
        e += 1

    # Calculate private key exponent
    d = pow(e, -1, phi)

    private_key = (d, n)
    public_key = (e, n)

    return private_key, public_key



# Generate SHA-256 hash of message
# Used for authentication (Digital Signature)
def generate_hash(text):
    encoded_text = text.encode()
    hash_object = hashlib.sha256(encoded_text)

    return hash_object.hexdigest()



# RSA Encryption
# Used for:
# 1. Encrypting digital signature using sender private key
# 2. Encrypting session key using receiver public key
def rsa_encrypt(key, message):
    e, n = key

    cipher_text = []

    for character in message:
        ascii_value = ord(character)
        encrypted_value = pow(ascii_value, e, n)

        cipher_text.append(encrypted_value)

    return cipher_text



# RSA Decryption
def rsa_decrypt(key, cipher_text):
    d, n = key

    plain_text = ""

    for encrypted_value in cipher_text:
        ascii_value = chr(pow(encrypted_value, d, n))
        plain_text += ascii_value

    return plain_text



# Symmetric Encryption
# Here XOR operation is used instead of AES for demonstration
def symmetric_encrypt(data, key):

    cipher_text = []

    for byte in data:
        cipher_text.append(byte ^ key)

    return bytes(cipher_text)



# Symmetric Decryption
def symmetric_decrypt(cipher_text, key):

    plain_text = []

    for byte in cipher_text:
        plain_text.append(byte ^ key)

    return bytes(plain_text)



if __name__ == "__main__":


    # Alice key pair
    private_key_alice, public_key_alice = generate_key()

    # Bob key pair
    private_key_bob, public_key_bob = generate_key()


    # Symmetric session key
    session_key = 123


    original_message = "The name of my country is Bangladesh"



    # ================= SENDER SIDE =================


    # Step 1: Generate hash of original message
    message_hash = generate_hash(original_message)


    # Step 2: Create digital signature
    # Hash is encrypted using sender private key
    encrypted_signature = rsa_encrypt(
        private_key_alice,
        message_hash
    )


    # Step 3: Attach signature with message
    message_with_signature = (
        str(encrypted_signature)
        + "|"
        + original_message
    )


    # Step 4: Compress message
    compressed_message = zlib.compress(
        message_with_signature.encode()
    )


    # Step 5: Encrypt compressed data using symmetric encryption
    encrypted_message = symmetric_encrypt(
        compressed_message,
        session_key
    )


    # Step 6: Encrypt session key using receiver public key
    encrypted_session_key = rsa_encrypt(
        public_key_bob,
        str(session_key)
    )


    # Send encrypted message + encrypted session key
    transmitted_data = (
        str(encrypted_message)
        + "|"
        + str(encrypted_session_key)
    )



    # ================= RECEIVER SIDE =================


    # Separate encrypted message and encrypted session key
    received_message, received_session_key = transmitted_data.split("|")


    # Convert string representation back to list
    received_message = eval(received_message)
    received_session_key = eval(received_session_key)



    # Step 7: Decrypt session key using Bob private key
    decrypted_session_key = rsa_decrypt(
        private_key_bob,
        received_session_key
    )


    # Step 8: Decrypt message using session key
    decrypted_compressed_message = symmetric_decrypt(
        received_message,
        int(decrypted_session_key)
    )


    # Step 9: Decompress message
    decrypted_message = zlib.decompress(
        decrypted_compressed_message
    )


    decrypted_message = decrypted_message.decode()



    # Separate signature and original message
    received_signature, received_text = decrypted_message.split("|")



    # Step 10: Verify digital signature
    # Decrypt signature using Alice public key
    decrypted_signature = rsa_decrypt(
        public_key_alice,
        eval(received_signature)
    )


    # Generate hash again from received message
    received_hash = generate_hash(received_text)



    # Authentication result
    print("Signature :", decrypted_signature)

    print("Hash      :", received_hash)


    if decrypted_signature == received_hash:
        print("PGP Authentication and Confidentiality Successful!")

    else:
        print("Verification Failed!")