import zmq

def main():
    # Создаем сокет
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("tcp://localhost:5555")

    while True:
        # Получаем сообщение
        message = socket.recv().decode()

        # Отправляем ответ
        response = "Hello, {}!".format(message)
        socket.send(response.encode())

if __name__ == "__main__":
    main()
