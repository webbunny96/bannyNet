import zmq

def main():
    # Создаем сокет
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://localhost:5555")

    # Отправляем сообщение
    message = "Hello, world!"
    socket.send(message.encode())

    # Получаем ответ
    response = socket.recv().decode()
    print(response)

if __name__ == "__main__":
    main()
