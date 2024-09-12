import socket
import threading

class Server:
    def __init__(self, host='127.0.0.1', port=5050):
        self.host = host
        self.port = port
        self.server_socket = None
        self.protocols = {
            '01': self.decode_protocol_01,
            '02': self.decode_protocol_02,
            '03': self.decode_protocol_03,
        }

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
        buffer = bytearray()
        while True:
            try:
                data = client_socket.recv(4096)
                if not data:
                    break

                buffer.extend(data)

                while len(buffer) >= 20: 
                    response = self.process_packet(buffer)
                    if response:
                        client_socket.sendall(response.encode())
            except Exception as e:
                print(f"Erro ao lidar com o cliente: {e}")
                break

        client_socket.close()
        print("Conexão fechada")

    def process_packet(self, buffer):
        try:
            if len(buffer) < 20:
                return

            start_bit = buffer[:2].hex()
            length = buffer[2:3].hex()
            protocol_number = buffer[3:4].hex()
            device_id = buffer[4:12].hex()
            information_serial_number = buffer[12:14].hex()
            error_check = buffer[14:16].hex()
            end_bit = buffer[16:18].hex()

            buffer.clear()

            print(f"Start Bit: {start_bit}")
            print(f"Length: {length}")
            print(f"Protocol Number: {protocol_number}")
            print(f"Device ID: {device_id}")
            print(f"Information Serial Number: {information_serial_number}")
            print(f"Error Check: {error_check}")
            print(f"End Bit: {end_bit}")

            return response
        
        except Exception as e:
            return f"Erro ao processar o pacote: {e}"

if __name__ == "__main__":
    server = Server()
