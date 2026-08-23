import hashlib
import zlib
import math

def key_genration_rsa():
    p,q=13,17
    n=p*q
    phi = (p-1)*(q-1)
    e=2
    while math.gcd(e,phi) !=1:
        e+=1
    d=pow(e,-1,phi)
    return n,e,d

def encryption(n,e,m):
    result = []
    for char in m:
        result.append((pow(ord(char),e,n)))
    return result

def decryptin(n,d,c):
    result =""
    for char in c:
        result+=chr(pow(char,d,n))
    return result

def symmetric(message,key):
    result =[]
    for byte in message:
        result.append(byte^key)
    return bytes(result)
def hash(message):
    encoded = message.encode()
    h = hashlib.sha256(encoded)
    return h.hexdigest()



n,e,d = key_genration_rsa()
m = "The name of our country is Bangladesh."

#sender site
#auth
h = hash(m)
ep1 = encryption(n,e,str(h))
concatenet1 = m + "|" +str(ep1)
z=zlib.compress(concatenet1.encode())


#conf
ks =11
ec = symmetric(z,ks)
ep2 = encryption(n,e,str(ks))
concatenet2 = str(ec) +"|"+ str(ep2)
print(f"Message send as: {concatenet2}")
#recevier site

#conf
message , key =concatenet2.split("|")
message = eval(message)
key = eval(key)
ks_dp1 = decryptin(n,d,key)
dc = symmetric(message,int(ks_dp1))
uz = zlib.decompress(dc).decode()

#auth
message2, h = uz.split("|")
dp = decryptin(n,d,eval(h))
print(dp)
ha = hash(message2)
print(ha)



if (dp==ha):
    print("su")
else:
    print("uns")


