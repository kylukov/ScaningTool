import socket
import json
from checkers import RunningProcessChecker, FirewallChecker
from process import Process
import time
import threading
from queue import Queue
import psutil
import subprocess


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


def is_process_secure(pid):
    try:
        # Получаем статус AppArmor
        apparmor_status = subprocess.check_output(["aa_status"])
        # Преобразуем вывод в строку
        apparmor_status = apparmor_status.decode("utf-8")
        # Ищем указанный PID в выводе
        if f"({pid})" in apparmor_status:
            # Если процесс связан с AppArmor, значит безопасен
            return True
        else:
            # Иначе процесс не связан с AppArmor, значит небезопасен
            return False
    except Exception:
        # Если возникла ошибка, считаем процесс небезопасным
        return False


def GetIPv4():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address


def ScanMacOs(target):
    socket.setdefaulttimeout(0.25)
    print_lock = threading.Lock()
    t_IP = socket.gethostbyname(target)
    print('Starting scan on host: ', t_IP)

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            con = s.connect((t_IP, port))
            with print_lock:
                print(port, 'is open')
            con.close()
        except:
            pass

    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()

    q = Queue()
    startTime = time.time()
    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for worker in range(1, 500):
        q.put(worker)

    q.join()
    print('Time taken:', time.time() - startTime)


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
    port_range = input("Введите диапазон портов для сканирования (например, 1-65535): ").split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])

    print(f"Начинаю сканирование портов {start_port} - {end_port} на {ip}...")

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"Port {port} is open: Name {RunningProcessChecker.CheckSocket(port)}")
            GetProtocolType(port)
            GetSocketsInfo(ip, port)
        s.close()


def GetSocketsInfo(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    data = {
        "Name: ": RunningProcessChecker.CheckSocket(port),
        "Protocol type: ": GetProtocolType(port),
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
    print(GetIPv4())
    Process.openedProcess()


if __name__ == '__main__':
    main()
