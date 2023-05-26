from main import GetIPv4
import socket

def AuthDetection(port):
    host = GetIPv4()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        sock.sendall(b'GET / HTTP/1.1\nHost: localhost\n\n')
        data = sock.recv(1024)
        if b'WWW-Authenticate' in data:
            return "+"
        else:
           return "-"
    except KeyboardInterrupt:
        sock.close()
        print('Функция была прервана')
    except socket.error as e:
        sock.close()
        print(f'Ошибка сокета: {e}')
    except Exception as e:
        sock.close()
        print(f'Неизвестная ошибка: {e}')
