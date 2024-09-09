import socket

class Client:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port

    def send_data(self, data):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            client_socket.sendall(data)
            
            # Receber a resposta do servidor
            response = client_socket.recv(4096)
            print(f"Resposta do servidor: {response.decode()}")

if __name__ == "__main__":
    client = Client()

    # Exemplo de dados para enviar (7 grupos de pacotes grandes)
    # Vamos começar com um exemplo de pacote. Aqui estamos enviando um pacote fictício.
    # Você pode ajustar o conteúdo e o tamanho do pacote conforme necessário.
    example_packet = bytes.fromhex('0001FF0203040506070809')  # Pacote de exemplo em hexadecimal

    client.send_data(example_packet)
