import socket


def GetProtocolType(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))

        if result == 0:
            protocol_name = socket.getservbyport(port)
            return protocol_name
        else:
            print(f"Port {port} is closed or unavailable")
    except:
        return