import psutil


def checkProcessSec(pid):
    # Получаем список всех запущенных процессов
    processes = psutil.process_iter()

    # Проходимся по всем процессам
    for process in processes:
        try:
            # Получаем информацию о процессе
            process_info = process.as_dict(attrs=['pid', 'name', 'cmdline'])

            # Проверяем, что процесс запущен из доверенного источника
            if 'trusted_application' not in process_info['cmdline']:
                print(f"Process {process_info['name']} with PID {process_info['pid']} is not trusted")
            else:
                print(f"Process {process_info['name']} with PID {process_info['pid']} is trusted")
        except psutil.NoSuchProcess:
            pass

