import socket

def getPort():
    start_port = 1  # Начальный порт для сканирования
    end_port = 65535  # Конечный порт для сканирования

    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", port))
                return port  # Возвращаем первый свободный порт
        except OSError:
            continue

    return None  # Возвращаем None, если не найден свободный порт