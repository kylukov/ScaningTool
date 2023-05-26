from sockets import RunningProcessChecker, Protocol, FirewallChecker
import socket


class Socket:
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.getIp(), port))
        self.name = RunningProcessChecker.CheckSocket(port)
        self.protocolType = Protocol.GetProtocolType(port)
        self.host = self.sock.getpeername()[0]
        self.port = self.sock.getpeername()[1]
        self.firewall = FirewallChecker.FirewallDetection(port)

    def getIp(self):
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        return ip_address

    def showSocket(self):
        print(f"  >  Name: {self.name}")
        print(f"  >  Protocol Type: {self.protocolType}")
        print(f"  >  Host: {self.host}")
        print(f"  >  Port: {self.port}")
        print(f"  >  FireWall: {self.firewall}")
