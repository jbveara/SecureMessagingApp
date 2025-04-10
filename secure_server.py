#!/usr/bin/env python
#
'''
Secure messaging server application for CYS6740 final project.
Base code from https://github.com/gnoubir/Network-Security-Tutorials/tree/master/Instant-Messaging-Base-Code, Guevara Noubir

'''

__author__      = "Jason Veara"


import zmq
import argparse
import random
import hashlib
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import messaging_app_pb2

#Preconfigured set of users enrolled in the system "Username" = (s,v)
UserSecrets = {
    "HanSolo": [1161199062579820832300718993376209447189957301612592005538219180755787960629606369609672090267317180134062873500812073522457023298603614374047334993457738,9688901845427093246078578497037987543455901000102155010085927043814015059050278173872896571951561731532228297337005338883766506715913706834975946852338506],
    "Chewbacca": [2837481299995422914018693968345500192605247770170883188369442177015701723308342458965226634243429721950214204824520637216008948734071096306841555653779100,3817758409867873505925193874965258173092727534197350558932668483793323335953073658393765043602508426847742037245820396414212652134231961134914177245137773],
    "DarthVader": [4160725073706826442055459416153902275265439884859923255740705478245003071416314101125438621601433514403530416527184168460340099097933433742919675667892889,8641127234064713362697675871213211053478425555656714149408941099862774259621609476171625968752548782684317753402409758381924348573199292947287699046306604]
}

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

parser.add_argument("-p", "--server-port", type=int,
                    default=5569,
                    help="port number that we want the server to use")

args = parser.parse_args()
server_port = args.server_port

#  Prepare our context and sockets
context = zmq.Context()

# Bind server socket, we are using REQ-REP pattern
server = context.socket(zmq.REP)
server.bind("tcp://*:%s" %(server_port))

# Initialize dictionary that maintains information about currently logged in users
logged_users = dict()
logged_ident = dict()

def cryptrand(n: int = 1024):
    '''Returns randomly generated number'''
    return random.SystemRandom().getrandbits(n) % N

def H(*args) -> int:
    """A one-way hash function."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)

def encrypt(payload, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES256(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(payload)
    return encrypted_payload, iv

def decrypt(encrypted_payload, key, iv):
    cipher = Cipher(algorithms.AES256(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    payload = decryptor.update(encrypted_payload)
    return payload

def client_login(message):
    '''Client login subroutine'''
    print('Processing Login...\n')

    #Parse login request message
    login_request = messaging_app_pb2.LoginRequest()
    login_request.ParseFromString(message[1])

    #Server receives username and A
    new_user = login_request.username
    big_a = int(login_request.A.hex(),16)

    #Server chooses b, c1, and 32-bit u value. Sends B = g^b+g^Wmodp, u, s, and c1 B to client
    b = cryptrand()
    c1 = cryptrand()
    u = cryptrand(32)
    secret = UserSecrets.get(new_user)
    s = secret[0]
    v = secret[1]
    big_b = (v+pow(g,b,N)) % N
    login_reply = messaging_app_pb2.LoginReply()
    login_reply.s = s.to_bytes(64)
    login_reply.u = u.to_bytes(64)
    login_reply.B = big_b.to_bytes(64)
    login_reply.c1 = c1.to_bytes(64)
    server.send(b'LOGIN_REPLY',flags=zmq.SNDMORE)
    server.send(login_reply.SerializeToString())

    #Server calculates shared key
    SessionKey = pow(big_a*pow(v,u,N),b,N)
    SessionKey = H(SessionKey)

    #Server waits for response
    message = server.recv_multipart()
    key_confirm = messaging_app_pb2.KeyConfirm()
    key_confirm.ParseFromString(message[1])

    c1_encrypted = key_confirm.c1_encrypted
    iv = key_confirm.iv
    c2 = int(key_confirm.c2.hex(),16)

    #Server validates session key, check D{c1_encrypted} == c1
    c1_received = decrypt(c1_encrypted,SessionKey.to_bytes(32),iv)

    if c1_received.hex() == c1.to_bytes(64).hex():
        print('Keys valid')
        
        #Server sends proof of session key to client E{c2} and iv used for AES CTR mode
        c2_encrypted,iv = encrypt(c2.to_bytes(64),SessionKey.to_bytes(32))

        key_reply = messaging_app_pb2.KeyReply()
        key_reply.c2_encrypted = c2_encrypted
        key_reply.iv = iv

        server.send(b'KEY_REPLY',flags=zmq.SNDMORE)
        server.send(key_reply.SerializeToString())

        #Server waits for Final User registration
        encrypted_message = server.recv_multipart()

        message = decrypt(encrypted_message[2],SessionKey.to_bytes(32),encrypted_message[1])

        register_user = messaging_app_pb2.RegisterUser()
        register_user.ParseFromString(message)

        logged_users[register_user.username] = [register_user.IP_Address,register_user.port,register_user.PublicKey.decode('utf-8')]
        logged_ident[register_user.username] = SessionKey

        print(logged_users)

        #Send Ack
        payload = b'Welcome %s!' % bytes(register_user.username, 'utf-8')
        encrypted_payload, iv = encrypt(payload,SessionKey.to_bytes(32))
        server.send(iv,flags=zmq.SNDMORE)
        server.send(encrypted_payload)
        
    else:
        print('Keys invalid')
        key_reply = messaging_app_pb2.KeyReply()
        key_reply.c2_encrypted = bytes(64)
        key_reply.iv = bytes(16)
        server.send(b'ABORT',flags=zmq.SNDMORE)
        server.send(key_reply.SerializeToString())

def list_request(message):
    '''Process received list request'''
    print('Processing List request\n')

    list_request = messaging_app_pb2.ListRequest()
    list_request.ParseFromString(message[1])

    if list_request.username in logged_users:
        list_reply = messaging_app_pb2.ListReply()
        json_logged_users = json.dumps(logged_users)
        list_reply.Users = bytes(json_logged_users,'utf-8') 

        SessionKey = logged_ident[list_request.username]

        encrypted_payload, iv = encrypt(list_reply.SerializeToString(),SessionKey.to_bytes(32))

        server.send(iv,flags=zmq.SNDMORE)
        server.send(encrypted_payload)


def main():
    # main loop waiting for users messages
    poll = zmq.Poller()
    poll.register(server, zmq.POLLIN)

    while(True):
        sock = dict(poll.poll())

        if server in sock and sock[server] == zmq.POLLIN:
            message = server.recv_multipart()

            if message[0]== b'LIST_REQUEST':
                print("Received [%s] message" % message[0])
                list_request(message)
            elif message[0] == b'LOGIN_REQUEST':
                print("Received [%s] message" % message[0])
                client_login(message)
            else:
                print("Received [%s] message" % message[0])
                print('Dropping unknown message')

if __name__ == "__main__":
    main()


    