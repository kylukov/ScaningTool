import os
import process.Process


def killProcess(pid):
    os.kill(pid, 15)


def DetectProcess():
    a = process.Process.openedProcess()
    for item in a:
        if "Google" in item:
            killProcess(int(item[item.find("PID")+4:-1]))