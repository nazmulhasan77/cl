import hashlib 
import math
import zlib


def rsa():
    p,q=17,13
    n=p*q
    phi =(p-1)*(q-1)
    e = 2
    while math.gcd(e,phi)!=1:
        e+=1
    d= pow(e,-1,phi)
    return n,e,d

def encryption(n,e,text):
    restlt = []
    for char in (text):
        m = ord(char)
        restlt.append(pow(m,e,n))
    return restlt

def decryption(n,d,text):
    result = ""
    for c in (text):
        result+=chr(pow(c,d,n))
    return result

def symmetric(data,key):
    result =[]
    for c in data:
        result.append(c^key)
    return bytes(result)


m="The name of our country is Bangladesh"
n,e,d = rsa()
ks=11
z=zlib.compress(m.encode())
ec= symmetric(z,ks)
ep = encryption(n,e,str(ks))
concateneted = str(ec) + "|"+ str(ep)
print(f"Message sending as:{concateneted}")

#receiver
message , k = concateneted.split("|")
k=eval(k)
message=eval(message)
dp = decryption(n,d,k)
dc = symmetric(message,int(dp))
uz = zlib.decompress(dc).decode()
print(f"The message send:{m}")
print(f"The message received:{uz}")
if m==uz:
    print("Successfull")
else:
    print("Unsuccessfull")

