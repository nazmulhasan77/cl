import math
import hashlib as hs
import zlib 
def key_genaration_rsa():
    p = 17
    q=13
    n=p*q
    phi =(p-1)*(q-1)
    e=2
    while math.gcd(e,phi)!=1:
        e+=1
    d = pow(e,-1,phi)
    return n,e,d
def encryption(n,e,text):
    result = []
    for char in text:
        m = ord(char)
        result.append(pow(m,e,n))
    return result
def decryption(n,d,text):
    result =""
    for c in text:
        result+=chr(pow(c,d,n))
    return result
def hash(text):
    encoded = text.encode()
    hash_value = hs.sha256(encoded)
    return hash_value.hexdigest()

text = "The name of my country is Bangladesh"
n,e,d = key_genaration_rsa()
print(n,e,d)
print(f"original Message : {text}")
#sender site
h = hash(text)
encrypteda_hash = encryption(n,e,h)
concatenated_massege = str(encrypteda_hash) + "|" + text
z=zlib.compress(concatenated_massege.encode())
print(f"Send message as : {z}")

#recevier site 
received_message = z
uz = zlib.decompress(received_message)
uz=uz.decode()
encrypteda_hash,message  = uz.split("|")
received_h = decryption(n,d,eval(encrypteda_hash))
h= hash(message)

print(message)

print(received_h)
print(h)
if (received_h == h):
    print("Message recevied with authenticity successfully")
else:
    print("Unsuccessfull")
