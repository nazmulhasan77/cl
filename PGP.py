from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1
import zlib


# ---- key generation ----
key = RSA.generate(1024)
private_key, public_key = key, key.publickey()


print("N : ", key.n)
print("E : ", key.e)
print("D : ", key.d)


# ----------- Sender Side -----------
# Step 1: Original message
message = "This is a confidential message"

# Step 2: SHA-1 hash
hash_obj = SHA1.new(message.encode())

# Step 3: Encrypt hash with private key
signature = pkcs1_15.new(private_key).sign(hash_obj)

# print( signature)

# Step 4: Concatenate signature + message
packet = signature + message.encode()

# Step 5: Compress
compressed_packet = zlib.compress(packet)

print("Message is sent.")
# print send message and hash
print("Original Message:", message)
print("SHA-1 Hash:", hash_obj.hexdigest())


# ----------- Receiver Side -----------
# Step 6: Decompress
decompressed_packet = zlib.decompress(compressed_packet)

# Step 7: Separate signature and message
received_signature = decompressed_packet[:128]
received_message = decompressed_packet[128:].decode()

# print(f"Received Signature: {received_signature}")

# Step 8: Generate new hash
new_hash = SHA1.new(received_message.encode())

# Step 9: Verify using sender public key
try:
    pkcs1_15.new(public_key).verify(new_hash, received_signature)

    print("\nMessage is AUTHENTIC")
    print("Message:", received_message)
    # print received message and hash
    print("SHA-1 Hash of Received Message:", new_hash.hexdigest())

except (ValueError, TypeError):

    print("Authentication Failed")
    print("Message is NOT authentic")