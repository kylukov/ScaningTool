import socket, time
import json
from checkers import RunningProcessChecker, FirewallChecker



def GetIPv4():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address


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


def ScanPort():
    ip = GetIPv4()
    port_range = input("Введите диапазон портов для сканирования (например, 1-1000): ").split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])

    print(f"Начинаю сканирование портов {start_port} - {end_port} на {ip}...")

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"Порт {port} открыт")
            GetSocketsInfo(ip, port)

        s.close()


def GetSocketsInfo(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    data = {
        "Name: ": RunningProcessChecker.CheckSocket(port),
        "Dangerous: ": "dangerous" if port in open("dangerous.txt", 'r') else "neutral",
        "Host: ": sock.getpeername()[0],
        "Port: ": sock.getpeername()[1],
        "Socket family: ": sock.family,
        "Socket type: ": sock.type,
        "Firewall": FirewallChecker.FirewallDetection(port),
    }

    with open("data.json", 'a') as f:
        f.write(json.dumps(data) + '\n')


def main():
    ScanPort()


if __name__ == '__main__':
    main()
