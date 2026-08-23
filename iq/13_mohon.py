from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import zlib
import base64

#=========================
# Base64 Encoding and Decoding for printing
#=========================
def b_en(data):
    return base64.b64encode(data).decode()

def b_de(data):
    return base64.b64decode(data.encode())

# =========================
# KEY GENERATION
# =========================

Kr_A = RSA.generate(1024)
Ku_A = Kr_A.publickey()

Kr_B = RSA.generate(1024)
Ku_B = Kr_B.publickey()


# =========================
# SENDER SIDE
# =========================

message = "This is a confidential and authentic message"


# ---------- AUTHENTICATION ----------

# 1. Hash message
h_obj = SHA256.new(message.encode())
print("H :", b_en(h_obj.digest()))

# 2. Sign hash with private key
signature = pkcs1_15.new(Kr_A).sign(h_obj)
print("S :", b_en(signature))

# 3. Signature + Message
auth_packet = signature + message.encode()
# print("Auth Packet :", b_en(auth_packet))

# 4. Compress authentication output
compressed_auth = zlib.compress(auth_packet, level=9)
# print("Compressed:", b_en(compressed_auth))


# ---------- CONFIDENTIALITY ----------

# 5. Generate 128-bit session key
Ks = get_random_bytes(16)
print("Session Key :", b_en(Ks))

# 6. Encrypt compressed authentication data
#    AES block size = 16 bytes
aes_cipher = AES.new(Ks, AES.MODE_ECB)
# print("AES Key :", b_en(aes_cipher))
padded_data = pad(compressed_auth, AES.block_size)
ciphertext = aes_cipher.encrypt(padded_data)


# 7. Encrypt session key using receiver's public key
rsa_cipher = PKCS1_OAEP.new(Ku_B)

encrypted_session_key = rsa_cipher.encrypt(Ks)


print("Message is sent.")
print("Original Message:", message)


# Write encrypted session key and ciphertext to a file in a separate line each
with open("secure_data.txt", "w") as file:
    file.write(b_en(encrypted_session_key) + '\n')
    file.write(b_en(ciphertext) + '\n')




# =========================
# RECEIVER SIDE
# =========================

# ---------- CONFIDENTIALITY ----------
#Read encrypted session key and ciphertext from the file
with open("secure_data.txt","r") as file:
    encrypted_session_key=b_de(file.readline().strip())
    ciphertext=b_de(file.readline().strip())
  


# 9. Recover session key using private key
rsa_cipher = PKCS1_OAEP.new(Kr_B)

Ks = rsa_cipher.decrypt(encrypted_session_key)


# 10. Decrypt ciphertext
aes_cipher = AES.new(Ks, AES.MODE_ECB)
padded_data = aes_cipher.decrypt(ciphertext)
compressed_auth = unpad(padded_data, AES.block_size)



# ---------- AUTHENTICATION ----------

# 11. Decompress
auth_packet = zlib.decompress(compressed_auth)


# 12. Separate signature and message
signature_size = Ku_A.size_in_bytes()

received_signature = auth_packet[:signature_size]
received_message = auth_packet[signature_size:].decode()

# Compremised Scenario
# received_message = received_message + " with some modification"



# 13. Generate new hash
new_hash = SHA256.new(received_message.encode())

print("Received Message :", received_message)
print("Received Signature :", b_en(received_signature))
print("New Hash :", b_en(new_hash.digest()))


# 14. Verify signature
try:

    pkcs1_15.new(Ku_A).verify(
        new_hash,
        received_signature
    )

    print("\nMessage is AUTHENTIC and CONFIDENTIAL")
    print("Received Message:", received_message)

except (ValueError, TypeError):

    print("\nAuthentication and Confidentiality Failed")
    print("Message is NOT authentic")