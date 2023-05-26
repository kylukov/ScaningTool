import psutil
import subprocess


def openedProcess():
    current_pid = psutil.Process().pid
    a = []

    # перебираем все открытые файлы и соответствующие им процессы
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            # получаем список файловых дескрипторов процесса
            files = proc.open_files()

            # выводим имя процесса, если он открывал файл
            for file in files:
                if file and file.fd and proc.pid != current_pid:
                    #print(f"Process '{proc.name()}' (PID: {proc.pid}). {is_process_secure(current_pid)}")
                    a.append(str(f"Process {proc.name()} (PID {proc.pid})"))


        except Exception as e:
            # если возникает ошибка при попытке получения списка файловых дескрипторов, игнорируем процесс
            pass
    for item in set(a):
        print(item)


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