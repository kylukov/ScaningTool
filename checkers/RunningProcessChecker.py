import psutil


def CheckSocket(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port and conn.status == 'LISTEN':
            pid = conn.pid  # получаем идентификатор процесса, который слушает порт
            process = psutil.Process(pid)  # создаем объект процесса
            return process.name()