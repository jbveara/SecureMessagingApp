import zmq
import argparse
import test_app_pb2

parser = argparse.ArgumentParser()

parser.add_argument("-p", "--server-port", type=int,
                    default=5569,
                    help="port number of server to connect to")

args = parser.parse_args()

#  Prepare our context and sockets
context = zmq.Context()

# Bind REP socket to context
socket = context.socket(zmq.REP)
socket.bind("tcp://*:%s" %(args.server_port))

while True:
    message = socket.recv_multipart()

    if message[0] == b'Ping':
        payload = test_app_pb2.Ping()
        payload.ParseFromString(message[1])
        print(payload)

    payload = test_app_pb2.Pong()

    

    socket.send(b'Pong')