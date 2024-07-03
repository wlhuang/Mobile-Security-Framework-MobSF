import sys
import socket

if len(sys.argv) < 2:
    print("Argument Error")
    sys.exit(1)

port = int(sys.argv[1])

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("localhost", port))
        except OSError as e:
            if e.errno == socket.errno.EADDRINUSE:
                return True
            else:
                # Unexpected OSError, re-raise the exception
                raise
    return False

if is_port_in_use(port):
    print(f"\nPort \033[1;37m{port}\033[0m is already in use. Please wait as we terminate the current process. Exiting...\n")
    sys.exit(1)
else:
    pass
