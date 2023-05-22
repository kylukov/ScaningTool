import socket
from main import GetIPv4


def FirewallDetection(port):
    host = GetIPv4()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            return "-"
        else:
            return "?"
    except socket.gaierror:
        print('Ошибка при подключении к хосту')
    finally:
        sock.close()
