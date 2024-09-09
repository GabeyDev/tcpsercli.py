import socket
import threading

class Server:
        def init(self, host='0.0.0.0', port=12345):
            self.host = host
            self.port = port
            self.server_socket = None
            self.clients = []

        def start(self):
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Servidor iniciado em {self.host}:{self.port}")

            while True:
                client_socket, client_address = self.server_socket.accept()
                print(f"Conexão estabelecida com {client_address}")

                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()

        def handle_client(self, client_socket):
            while True:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    print(f"Recebido do cliente: {data.decode()}")
                    response = "Olá, cliente!"
                    client_socket.sendall(response.encode())
                except Exception as e:
                    print(f"Erro ao lidar com o cliente: {e}")
                    break

            client_socket.close()
            print("Conexão fechada")

if name == "main":
        server = Server()
        server.start()
