#!/usr/bin/env python
#
'''
Secure messaging client application for CYS6740 final project.
Base code from https://github.com/gnoubir/Network-Security-Tutorials/tree/master/Instant-Messaging-Base-Code, Guevara Noubir
'''

__author__      = "Jason Veara"

import socket
import zmq
import sys
import argparse
import messaging_app_pb2
import hashlib
import random
import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

NOT_REGISTERED = 0
REGISTERED = 1

HOST_NAME = socket.gethostname()
HOST_IP = socket.gethostbyname(HOST_NAME)

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

parser.add_argument("-s", "--server",
                    default="localhost",
                    help="Server IP address or name")

parser.add_argument("-p", "--server-port", type=int,
                    default=5569,
                    help="port number of server to connect to")

parser.add_argument("-u", "--user", required=True,
                    help="name of user")

parser.add_argument("-up", "--user-port", type = int,
                    default=5500, 
                    help="local port number to receive messages from other useres")

args = parser.parse_args()
username = args.user
serverIP = args.server
serverPORT = args.server_port
userPORT = args.user_port

# Initialize state of client
status = NOT_REGISTERED

#  Prepare our context
context = zmq.Context()

# Bind receiving socket to receive any messages sent to us by other clients
receive = context.socket(zmq.REP)
receive.bind("tcp://%s:%s" %(HOST_IP, userPORT))

# Initialize dictionary to store session keys with other clients
active_sessions = dict()

# Function to print a prompt character
def print_prompt(c):
    sys.stdout.write(c)
    sys.stdout.flush()

def cryptrand(n: int = 1024):
    return random.SystemRandom().getrandbits(n) % N

def H(*args) -> int:
    """A one-way hash function."""
    a = ":".join(str(a) for a in args)
    return int(hashlib.sha256(a.encode("utf-8")).hexdigest(), 16)

def encrypt(payload, key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_payload = encryptor.update(payload)
    return encrypted_payload, nonce

def decrypt(encrypted_payload, key, nonce):
    cipher = Cipher(algorithms.AES256(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    payload = decryptor.update(encrypted_payload)
    return payload

def gen_PubPriv_key():
    '''Function that generates a new public/private key pair for the client app to use for messaging'''
    private_key = rsa.generate_private_key (public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_key = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(b'Password'))
    public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.PKCS1)

    return private_key, public_key

def client_login():
    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(serverIP, serverPORT))
    
    #Client chooses random a, sends username and A = g^a_modp to the server
    a = cryptrand()
    big_a = pow(g, a, N)

    login_request = messaging_app_pb2.LoginRequest()
    login_request.username = username
    login_request.A = big_a.to_bytes(64)

    client.send(b'LOGIN_REQUEST',flags=zmq.SNDMORE)
    client.send(login_request.SerializeToString())

    #Client waits for response
    message = client.recv_multipart()
    login_reply = messaging_app_pb2.LoginReply()
    login_reply.ParseFromString(message[1])

    big_b = int(login_reply.B.hex(),16)
    u = int(login_reply.u.hex(),16)
    s = int(login_reply.s.hex(),16)
    c1 = int(login_reply.c1.hex(),16)

    #Abort if B received is 0 mod N
    if big_b % N == 0 :
        print('Invalid B received during SRP key exchange')
        status = NOT_REGISTERED
        SessionKey = 0
        K_priv = 0
        return SessionKey, K_priv, status


    #Client asks user for password
    password = input("Please enter your password:\n")
    x = H(s,password)

    # Client calculates share key
    SessionKey = pow(big_b-pow(g,x,N),a+u*x,N)
    SessionKey = H(SessionKey)

    #Client sends proof of seesion key to server (encrypted_c1) with value c2, and nonce used for AES CBC mode
    c2 = cryptrand()
    c1_encrypted,nonce = encrypt(c1.to_bytes(64),SessionKey.to_bytes(32))
    key_confirm = messaging_app_pb2.KeyConfirm()
    key_confirm.c1_encrypted = c1_encrypted
    key_confirm.c2 = c2.to_bytes(64)
    key_confirm.nonce = nonce
    client.send(b'KEY_CONFIRM',flags=zmq.SNDMORE)
    client.send(key_confirm.SerializeToString())
    
    #Client waits for response
    message = client.recv_multipart()
    key_reply = messaging_app_pb2.KeyReply()
    key_reply.ParseFromString(message[1])
    c2_encrypted = key_reply.c2_encrypted
    nonce = key_reply.nonce

    #Client validates session key, check D{c2_encrypted} == c2
    c2_received = decrypt(c2_encrypted,SessionKey.to_bytes(32),nonce)

    if c2_received.hex() == c2.to_bytes(64).hex():
        print('Keys valid')
        
        #Generate Priv/Public Key
        K_priv, K_pub = gen_PubPriv_key()

        #Register User information with server
        register_user = messaging_app_pb2.RegisterUser()
        register_user.username = username
        register_user.IP_Address = HOST_IP
        register_user.port = userPORT
        register_user.PublicKey = K_pub

        payload , nonce = encrypt(register_user.SerializeToString(),SessionKey.to_bytes(32))

        client.send(b'REGISTER_USER',flags=zmq.SNDMORE)
        client.send(nonce,flags=zmq.SNDMORE)
        client.send(payload)
        
        #Receive Registration ack
        encrypted_message = client.recv_multipart()
        message = decrypt(encrypted_message[1],SessionKey.to_bytes(32),encrypted_message[0])
        print(message)

        status = REGISTERED

        return SessionKey, K_priv, status
    
    else:
        print('Log-in Failed')
        status = NOT_REGISTERED
        SessionKey = 0
        K_priv = 0
        return SessionKey, K_priv, status
    
def send_list(SessionKey):
    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(serverIP, serverPORT))

    list_request = messaging_app_pb2.ListRequest()
    list_request.username = username

    client.send(b"LIST_REQUEST",flags=zmq.SNDMORE)
    client.send(list_request.SerializeToString())

    encrypted_message = client.recv_multipart()
    message = decrypt(encrypted_message[1],SessionKey.to_bytes(32),encrypted_message[0])

    list_reply = messaging_app_pb2.ListReply()
    list_reply.ParseFromString(message)

    logged_users = json.loads(list_reply.Users)

    return logged_users

def send_message(user_message, user_info, Key):
    '''Function to send a message to another user'''
    print('Sending message...')
    
    encrypted_message, nonce = encrypt(user_message.encode('utf-8'), Key.to_bytes(32))

    message = messaging_app_pb2.Message()
    message.username = username
    message.encrypted_message = encrypted_message
    message.nonce = nonce

    destinationIP  = user_info[0]
    destinationPort = user_info[1]

    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(destinationIP, destinationPort))

    client.send(b'MESSAGE',flags=zmq.SNDMORE)
    client.send(bytes(username, 'utf-8'),flags=zmq.SNDMORE)
    client.send(message.SerializeToString())


def receive_message(message):
    received_message = messaging_app_pb2.Message()

    user = message[1]

    Key = active_sessions[user.decode('utf-8')]

    received_message.ParseFromString(message[2])

    print(received_message.nonce.hex())

    decrypted_message = decrypt(received_message.encrypted_message,Key.to_bytes(32), received_message.nonce)

    receive.send(message[2])

    return decrypted_message, user

def establish_key(user_info, K_priv):
    '''D-H key exchange to establisth a symmetric key with another user '''
    destinationIP  = user_info[0]
    destinationPort = user_info[1]

    #Generate sending user D-H key contribution
    a = int.from_bytes(os.urandom(64))
    contrib_a = pow(g,a,N)
    contrib_a = contrib_a.to_bytes(64)

    private_key = serialization.load_pem_private_key(K_priv,b'Password')

    signature = private_key.sign(
        H(contrib_a,username).to_bytes(64),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(destinationIP, destinationPort))

    establish_key_request = messaging_app_pb2.EstablishKeyRequest()
    establish_key_request.contrib_a = contrib_a
    establish_key_request.username = username
    establish_key_request.signature = signature

    #Send Key contribution
    client.send(b'ESTABLISH_KEY_REQUEST',flags=zmq.SNDMORE)
    client.send(establish_key_request.SerializeToString())

    #Wait for receiving user D-H Key contribution
    message = client.recv_multipart()

    #Verify signature from receiving user D-H Key contribution
    establish_key_reply = messaging_app_pb2.EstablishKeyReply()
    establish_key_reply.ParseFromString(message[1])

    destination_PubKey = serialization.load_pem_public_key(bytes(user_info[2],'utf-8'))
    try:
        destination_PubKey.verify(
            establish_key_reply.signature,
            H(establish_key_reply.contrib_b,establish_key_reply.username).to_bytes(64),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            hashes.SHA256()
            )
    except:
        print('Signature from establish key request is invalid')
        Key = 0
        return Key  
    
    #Calculate Session Key
    Message_SessionKey = pow(int.from_bytes(establish_key_reply.contrib_b),a,N)
    Message_SessionKey = H(Message_SessionKey)

    #Send Session Key confirmation
    c1_encrypted, nonce = encrypt(establish_key_reply.c1,Message_SessionKey.to_bytes(32))
    key_confirm = messaging_app_pb2.KeyConfirm()
    key_confirm.c1_encrypted = c1_encrypted
    key_confirm.nonce = nonce
    c2 = cryptrand()
    key_confirm.c2 = c2.to_bytes(64)

    client.send(b'KEY_CONFIRM',flags=zmq.SNDMORE)
    client.send(key_confirm.SerializeToString())

    #Wait for Mesge Key reply
    message = client.recv_multipart()
    key_reply = messaging_app_pb2.KeyReply()
    key_reply.ParseFromString(message[1])
    c2_encrypted = key_reply.c2_encrypted
    nonce = key_reply.nonce

    #Client validates session key, check D{c2_encrypted} == c2
    c2_received = decrypt(c2_encrypted,Message_SessionKey.to_bytes(32),nonce)

    if c2_received.hex() == c2.to_bytes(64).hex():
        print('Keys valid')
        return Message_SessionKey
    
    else:
        print('Key Establishment failed')
        Key = 0
        return Key

def process_key_est_req(message,users,K_priv):
    '''Process an incoming key establishment request'''
    print('Processing key establishment request')

    establish_key_request = messaging_app_pb2.EstablishKeyRequest()
    establish_key_request.ParseFromString(message[1])
    requesting_user = establish_key_request.username

    #Verify signature from sending user D-H Key contribution
    if establish_key_request.username in users:
        user_info = users[establish_key_request.username]
        public_key = serialization.load_pem_public_key(bytes(user_info[2],'utf-8'))

        try:
            public_key.verify(
                establish_key_request.signature,
                H(establish_key_request.contrib_a,establish_key_request.username).to_bytes(64),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                    ),
                hashes.SHA256()
                )
        except:
            print('Signature from establish key request is invalid')
            Key = 0
            return Key
        
        #Generate receiving user D-H Key contribution
        b = int.from_bytes(os.urandom(64))
        contrib_b = pow(g,b,N)
        contrib_b = contrib_b.to_bytes(64)

        private_key = serialization.load_pem_private_key(K_priv,b'Password')

        signature = private_key.sign(
            H(contrib_b,username).to_bytes(64),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        establish_key_reply = messaging_app_pb2.EstablishKeyReply()
        establish_key_reply.contrib_b = contrib_b
        establish_key_reply.username = username
        establish_key_reply.signature = signature
        c1 = cryptrand()
        establish_key_reply.c1 = c1.to_bytes(64)

        #Send Key contribution
        receive.send(b'ESTABLISH_KEY_REQUEST',flags=zmq.SNDMORE)
        receive.send(establish_key_reply.SerializeToString())

        #Calculate Session Key
        Message_SessionKey = pow(int.from_bytes(establish_key_request.contrib_a),b,N)
        Message_SessionKey = H(Message_SessionKey)

        #Wait for Message Session Key confirmation
        message = receive.recv_multipart()

        #Confirm Message Session Key
        key_confirm = messaging_app_pb2.KeyConfirm()
        key_confirm.ParseFromString(message[1])

        c1_encrypted = key_confirm.c1_encrypted
        nonce = key_confirm.nonce
        c2 = int(key_confirm.c2.hex(),16)

        c1_received = decrypt(c1_encrypted,Message_SessionKey.to_bytes(32),nonce)

        if c1_received.hex() == c1.to_bytes(64).hex():
            print('Keys valid')
            
            #Server sends proof of session key to client E{c2} and nonce used for AES CBC mode
            c2_encrypted,nonce = encrypt(c2.to_bytes(64),Message_SessionKey.to_bytes(32))

            key_reply = messaging_app_pb2.KeyReply()
            key_reply.c2_encrypted = c2_encrypted
            key_reply.nonce = nonce

            receive.send(b'KEY_REPLY',flags=zmq.SNDMORE)
            receive.send(key_reply.SerializeToString())

            return Message_SessionKey, requesting_user

        else:
            key_reply = messaging_app_pb2.KeyReply()
            key_reply.c2_encrypted = bytes(64)
            key_reply.nonce = bytes(16)
            receive.send(b'ABORT',flags=zmq.SNDMORE)
            receive.send(key_reply.SerializeToString())
            raise Exception("Invalid key")

    else:
        raise Exception("received key establishment request from inactive user")
    
def logout(SessionKey):
    '''Function to send log out message and shut down program'''

    client = context.socket(zmq.REQ)
    client.connect("tcp://%s:%s" %(serverIP, serverPORT))

    logout_message = messaging_app_pb2.Logout()
    logout_message.username = username

    encrypted_message, nonce = encrypt(logout_message.SerializeToString(),SessionKey.to_bytes(32))

    client.send(b"LOGOUT",flags=zmq.SNDMORE)
    client.send(bytes(username,'utf-8'),flags=zmq.SNDMORE)
    client.send(nonce,flags=zmq.SNDMORE)
    client.send(encrypted_message)



def main():
    status = NOT_REGISTERED
    #Client application logs into server
    while status == NOT_REGISTERED:
        SessionKey, K_priv, status = client_login()

    # We are going to wait on both the socket for messages and stdin for command line input
    poll = zmq.Poller()
    poll.register(receive, zmq.POLLIN)
    poll.register(sys.stdin, zmq.POLLIN)
    
    while(True):
        sock = dict(poll.poll())

        # if message came on the socket
        if receive in sock and sock[receive] == zmq.POLLIN:
            message = receive.recv_multipart()

            # If MSG 
            if message[0] == b'ESTABLISH_KEY_REQUEST' and len(message) > 1:
                users = send_list(SessionKey)
                Key, user = process_key_est_req(message,users,K_priv)
                active_sessions[user] = Key
                print(active_sessions)
                print_prompt(' <- ')

            if message[0] == b'MESSAGE' and len(message) >1:
                print('Received message, attempting to decrypt')
                decrypted_message, user = receive_message(message)
                print('Message received from %s' % user)
                print(decrypted_message.decode('utf-8'))           

            # If error encountered by server
            if message[0] == b'ERR' and len(message) > 1:
                d = message[1] #base64.b64decode(message[1])
                print("\n <!> %s" % (d))
                print_prompt(' <- ')

        # if input on stdin -- process user commands
        elif sys.stdin.fileno() in sock and sock[0] == zmq.POLLIN:
            userin = sys.stdin.readline().splitlines()[0]
            print_prompt(' <- ')

            # get the first work on user input
            cmd = userin.split(' ', 2)

            # if it's list send "LIST", note that we should have used google protobuf
            if cmd[0] == 'LIST':
                users = send_list(SessionKey)
                print(users)

            if cmd[0] =='LOGOUT':  
                logout(SessionKey)
                sys.exit()

            # SEND command is sent as a three parts ZMQ message, as "SEND destination message"
            if cmd[0] == 'SEND' and len(cmd) > 2:
                destination = cmd[1]
                msg = cmd[2]
                
                #First send list command to get fresh list of active users
                users = send_list(SessionKey)

                if destination in users:    
                    user_info = users[destination]

                    if destination not in active_sessions:
                        Key = establish_key(user_info, K_priv)
                        active_sessions[destination] = Key
                        send_message(msg, user_info, Key)

                    else:   
                        Key = active_sessions[destination]
                        send_message(msg, user_info, Key)
                else:
                    print("%s is not online" % destination)


if __name__ == "__main__":
    main()

    