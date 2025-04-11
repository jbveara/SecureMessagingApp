# Secure Messaging Application
# CYS6740 Final Project, Spring 2025
# Author: Jason Veara

## Preconfigured User Credentials
The below users have accounts for the secure messaging app.  Their username:password credentials have already been loaded onto the server.


HanSolo:Falcon 
Chewbacca:GWhahwWHaha
DarthVader:IamyourFather

## System Pre-requisites
The system running the secure messaging client and/or server must have Python 3.10 or higher installed.  The following python libraries must also be installed. 

zmq
cryptography
protobuf

## System Use
1. Start the server applicaiton `secure_server.py`. The server will use a default port of 5569, unless otherwise specified by command line argument.
2. Start the client application `secure_client.py`. You must specify the username as a command line argument. You may optionally specifc the server IP address, server port, and user port values.
3. When prompted enter the user password.
4. Once you have logged in you will see the welcome message from the server.
5. The client can type the `LIST` command to get a list of active users.
6. The client can type the `SEND $USER $message` command.  Replace `$USER` with the username you wish to send a message to, and `$message` with the message you wish to send.
7. Once complete, the client can log out using the `LOGOUT` command.