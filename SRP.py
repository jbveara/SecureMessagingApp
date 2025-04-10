"""
An example SRP authentication

WARNING: Do not use for real cryptographic purposes beyond testing.
WARNING: This below code misses important safeguards. It does not check A, B, and U are not zero.

based on http://srp.stanford.edu/design.html
"""
import hashlib
import random
import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Note: str converts as is, str([1,2,3,4]) will convert to "[1,2,3,4]"
def H(*args) -> int:
    """A one-way hash function."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)

def cryptrand(n: int = 1024):
    return random.SystemRandom().getrandbits(n) % N

# A large safe prime (p = 2q+1, where q is prime)
# All arithmetic is done modulo p
# (generated using "openssl dhparam -text 1024")
N = """00:bf:2c:e1:8b:ba:84:70:72:bb:3e:8e:1d:13:10:
        fc:47:c0:27:ec:32:e1:03:79:b1:f0:c3:36:8a:d1:
        74:50:b9:54:f0:4c:db:88:03:f3:33:b3:e7:58:80:
        9e:28:e1:27:81:d0:b7:e9:0f:65:27:cd:29:6c:22:
        27:10:a7:ab:ef"""
     
N = int("".join(N.split()).replace(":", ""), 16)
g = 2  # A generator modulo N
F = '#0x' # Format specifier

print("#. H, N, g, are known beforehand to both client and server:")
print(f'{H = }\n{N = :{F}}\n{g = :{F}}')

print("\n0. server stores (user_name, g^W_modN) in its password database")

# The server must first generate the password verifier
user_name = "jason"        # Username
p = "password1234"  # Password
s = cryptrand() #salt
x = H(s,p)
v = pow(g,x,N)   # Password verifier

print(f'{user_name = }\n{p = }\n{s = :{F}}\n{x = :{F}}\n{v = :{F}}')

print("\n1. Client sends username and A = g^a_modp to the server")
a = cryptrand()
A = pow(g, a, N)
print(f'{user_name = }')
print(f'{A = :{F}}')

print("\n2. Server chooses b, c1, and 32-bit u value. Sends B = g^b+g^Wmodp, u, s, and c1 B to client")
b = cryptrand()
c1 = cryptrand()
u = cryptrand(32)
B = (v+pow(g,b,N)) % N
print(f'{s = :{F}}')
print(f'{B = :{F}}')
print(f'{u = :{F}}')
print(f'{c1 = :{F}}')

print("\n3. Client calculates shared key")
Sk_c = pow(B-pow(g,x,N),a+u*x,N)
Sk_c = H(Sk_c)
print(f'{Sk_c = :{F}}')


print("\n4. Server calculates shared key")
Sk_s = pow(A*pow(v,u,N),b,N)
Sk_s = H(Sk_s)
print(f'{Sk_s = :{F}}')

iv = os.urandom(16)

print("\n4. client sends proof of session key to server with value c2")
c2 = cryptrand()
cipher = Cipher(algorithms.AES256(Sk_c.to_bytes(32)), modes.CTR(iv), backend=default_backend())
encryptor = cipher.encryptor()
cipher_text = encryptor.update(c1.to_bytes(64))
print(cipher_text.hex())
print(f'{c2 = :{F}}')

print("\n5. Server validates c1 and sends c2")
cipher = Cipher(algorithms.AES256(Sk_s.to_bytes(32)), modes.CTR(iv), backend=default_backend())
decryptor = cipher.decryptor()
plain_text = decryptor.update(cipher_text)
print(plain_text.hex())
print(f'{c1 = :{F}}')

if int.from_bytes(plain_text) == c1:
    print('success')

