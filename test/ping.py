import socket
import zmq
import argparse
import test_app_pb2

HOST_NAME = socket.gethostname()
HOST_IP = socket.gethostbyname(HOST_NAME)

parser = argparse.ArgumentParser()

parser.add_argument("-p", "--server-port", type=int,
                    default=5569,
                    help="port number of server to connect to")

parser.add_argument("-s", "--server",
                    default="localhost",
                    help="Server IP address or name")

args = parser.parse_args()

#  Prepare our context
context = zmq.Context()

# Connect REQ socket to context
socket = context.socket(zmq.REQ)
socket.connect("tcp://%s:%s" %(args.server, args.server_port))

while True:

    payload = test_app_pb2.Ping()
    payload.msg = "ping"
    payload.ip_address = HOST_IP

    print ('message sent')
    socket.send(b'Ping',flags=zmq.SNDMORE)
    socket.send(payload.SerializeToString())


    message = socket.recv()

    print(message)

