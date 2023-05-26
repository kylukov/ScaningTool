import psutil


def checkProcessSec(pid):
    process = psutil.Process(pid)
    uids = process.uids()

    if uids[0] != user_id or uids[1] != group_id:
        print("Процесс запущен с недопустимыми уровнями привилегий")
    else:
        print("Процесс безопасен")
