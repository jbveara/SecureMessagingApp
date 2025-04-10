#Program used to create 3 users to enroll in the secure message app
#
# Users:
# HanSolo:Falcon
# Chewbacca:GWhahwWHaha
# DarthVader:IamyourFather
#

import hashlib
import random
import os
import argparse


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

#Parse Arguments
parser = argparse.ArgumentParser()

parser.add_argument("-u", "--username", type=str,
                    help="Username of user to enroll")

parser.add_argument("-p","--password", type=str,
                   help="Password of user to enroll")

args = parser.parse_args()

s = cryptrand()
x = H(s,args.password)
v = pow(g,x,N)

print(s)
print(v)


