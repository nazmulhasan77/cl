from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad

import base64
import zlib

def b_de(data):
    return base64.b64decode(data).decode()
def b_en(data):
    return base64.b64encode(data.encode())

#key
kra = RSA.generate(1024)
kua = kra.public_key()

krb = RSA.generate(1024)
kub =krb.public_key()

ks = get_random_bytes(16)
rsa_kra = pkcs1_15.new(kra)
rsa_krb = PKCS1_OAEP.new(krb)
rsa_kua = pkcs1_15.new(kua)
rsa_kub = PKCS1_OAEP.new(kub)

aes_ec = AES.new(ks,AES.MODE_ECB)
#aes_dc = AES.new(E_ks,AES.MODE_ECB)


m =" I love my parents"
#sender
h = SHA256.new(m.encode())
singnature = rsa_kra.sign(h)
packet_auth = singnature+m.encode()
z=zlib.compress(packet_auth)

padded_data = pad(z,AES.block_size)
cipher = aes_ec.encrypt(padded_data)
E_ks = rsa_kub.encrypt(ks)
final_packet = E_ks + cipher

#receiver 
rsa_size = kub.size_in_bytes()

E_ks = final_packet[:rsa_size]
E_cipher = final_packet[rsa_size:]

d_ks = rsa_krb.decrypt(E_ks)
aes_dc = AES.new(d_ks,AES.MODE_ECB)
d_cipher = aes_dc.decrypt(E_cipher)
z=unpad(d_cipher,AES.block_size)

packet_auth=zlib.decompress(z)
sing_size = kra.size_in_bytes()
signature = packet_auth[:sing_size]
m = packet_auth[sing_size:].decode()
h = SHA256.new(m.encode())

try:
    rsa_kua.verify(h,signature)
    print("successful")
except:
    print("Failed")
