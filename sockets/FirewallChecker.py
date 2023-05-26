import socket
from main import GetIPv4


def FirewallDetection(port):
    try:
        host = GetIPv4()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                return "Not detected"
            else:
                return True
        except socket.gaierror:
            print('Ошибка при подключении к хосту')
        finally:
            sock.close()
    except:
        return
