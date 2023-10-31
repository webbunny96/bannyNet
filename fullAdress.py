import socket
import psutil
import requests

def get_full_ip_address():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

# Пример использования
# full_ip_address = get_full_ip_address()
# print("Полный IP-адрес компьютера в сети:", full_ip_address)



def get_all_connection_ips():
    connections = psutil.net_connections(kind='inet')
    ip_addresses = set()

    for conn in connections:
        ip_addresses.add(conn.laddr[0])  # IP-адрес локальной стороны

    return list(ip_addresses)

# # Пример использования
# all_ip_addresses = get_all_connection_ips()
# for ip in all_ip_addresses:
#     print("IP-адрес:", ip)



def get_external_ip():
    try:
        response = requests.get("https://httpbin.org/ip")
        external_ip = response.json()["origin"]
        return external_ip
    except Exception as e:
        print("Не удалось получить внешний IP-адрес:", e)
        return None

external_ip = get_external_ip()
if external_ip:
    print("Ваш внешний IP-адрес:", external_ip)