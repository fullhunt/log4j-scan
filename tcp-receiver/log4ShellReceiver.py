import socket
import sys

# Create a socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Ensure that you can restart your server quickly when it terminates
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

# Set the client socket's TCP "well-known port" number
well_known_port = 80
sock.bind(('', well_known_port))

# Set the number of clients waiting for connection that can be queued
print("Listening on " + str(well_known_port))
sock.listen(20)

# loop waiting for connections (terminate with Ctrl-C)
try:
    while 1:
        # accept
        newSocket, address = sock.accept()
        newSocket.setblocking(0)
        sys.stdout.write("Connected from %s:%d..." % address)

        # log the IP address
        with open("output.txt", "a") as outfile:
            outfile.write("%s\n" % address[0])

        # close the connection quickly
        newSocket.close()
        print("disconnected")
finally:
    sock.close()
