"""
An example SRP authentication

WARNING: Do not use for real cryptographic purposes beyond testing.
WARNING: This below code misses important safeguards. It does not check A, B, and U are not zero.

based on http://srp.stanford.edu/design.html
"""
import hashlib
import random
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Note: str converts as is, str([1,2,3,4]) will convert to "[1,2,3,4]"
def H(*args) -> int:
    """A one-way hash function."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)

def cryptrand(n: int = 1024):
    return random.SystemRandom().getrandbits(n) % p

# A large safe prime (p = 2q+1, where q is prime)
# All arithmetic is done modulo p
# (generated using "openssl dhparam -text 1024")
p = """00:bf:2c:e1:8b:ba:84:70:72:bb:3e:8e:1d:13:10:
        fc:47:c0:27:ec:32:e1:03:79:b1:f0:c3:36:8a:d1:
        74:50:b9:54:f0:4c:db:88:03:f3:33:b3:e7:58:80:
        9e:28:e1:27:81:d0:b7:e9:0f:65:27:cd:29:6c:22:
        27:10:a7:ab:ef"""
     
p = int("".join(p.split()).replace(":", ""), 16)
g = 2  # A generator modulo p

k = H(p, g) # Multiplier parameter (k=3 in legacy SRP-6)

F = '#0x' # Format specifier

print("#. H, p, g, are known beforehand to both client and server:")
print(f'{H = }\n{p = :{F}}\n{g = :{F}}\n{k = :{F}}')

print("\n0. server stores (user_name, g^W_modp) in its password database")

# The server must first generate the password verifier
user_name = "jason"        # Username
weak_p = "password1234"  # Password
w = H(weak_p)      # Private key
v = pow(g, w, p)    # Password verifier

print(f'{user_name = }\n{weak_p = }\n{w = :{F}}\n{v = :{F}}')

print("\n1. Client sends username and A = g^a_modp to the server")
a = cryptrand()
A = pow(g, a, p)
print(f'{user_name = }')
print(f'{A = :{F}}')

print("\n2. Server chooses b, c1, and 32-bit u value. Sends B = g^b+g^Wmodp, u, and c1 B to client")
b = cryptrand()
c1 = cryptrand()
u = cryptrand(64)
B = (pow(g,b,p)+pow(g,w,p)) % p
print(f'{B = :{F}}')
print(f'{u = :{F}}')
print(f'{c1 = :{F}}')

print("\n3. client and server calculate shared key")
x = b*(a+(u*w))
Sk = pow(g,x,p)
print(f'{Sk = :{F}}')
key = os.urandom(64)
print(key.hex())


print("\n4. client sends proof of session key to server with value c2")


print("\n5. Server validates c1 and sends c2")



print()
