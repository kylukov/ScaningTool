import socket
import json
from sockets import Socket as sockets
from process import Process
import time
import threading
from queue import Queue


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


def ScanPort():
    a = []
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
            print(f"Port {port} is open")
            sk = sockets.Socket(port)
            sk.showSocket()
        s.close()


"""
def GetSocketsInfo(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    data = {
        "Name: ": RunningProcessChecker.CheckSocket(port),
        # "Protocol type: ": GetProtocolType(port),
        "Dangerous: ": "dangerous" if port in open("dangerous.txt", 'r') else "neutral",
        "Host: ": sock.getpeername()[0],
        "Port: ": sock.getpeername()[1],
        "Socket family: ": sock.family,
        "Socket type: ": sock.type,
        "Firewall": FirewallChecker.FirewallDetection(port),
    }
    with open("data.json", 'a') as f:
        f.write(json.dumps(data) + '\n')
"""

def main():
    print(GetIPv4())
    ScanPort()
    Process.openedProcess()


if __name__ == '__main__':
    main()
