import socket
import threading

class Server:
    def __init__(self, host='127.0.0.1', port=12345):
        self.host = host
        self.port = port
        self.server_socket = None

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

                while len(buffer) >= 9:  # Verifica se o buffer tem pelo menos o tamanho do pacote
                    if len(buffer) < 9:  # Ajusta para garantir o tamanho mínimo
                        break

                    # Extrair o pacote do buffer
                    start_bit = buffer[:2]
                    length = buffer[2:3]
                    info_serial_number = buffer[3:5]
                    error_check = buffer[5:7]
                    end_bit = buffer[7:9]

                    # Assumindo que o tamanho do pacote é fixo e extraindo o pacote completo
                    packet = buffer[:9]  # Ajuste o tamanho conforme necessário
                    buffer = buffer[9:]  # Remove o pacote processado do buffer

                    # Processa o pacote
                    response = self.process_packet(packet)

                    # Enviar resposta ao cliente
                    client_socket.sendall(response.encode())
            except Exception as e:
                print(f"Erro ao lidar com o cliente: {e}")
                break

        client_socket.close()
        print("Conexão fechada")

    def process_packet(self, packet):
        try:
            # Decodificar os campos do pacote
            start_bit = packet[:2]
            length = packet[2:3]
            info_serial_number = packet[3:5]
            error_check = packet[5:7]
            end_bit = packet[7:9]

            hex_start_bit = start_bit.hex()
            hex_length = length.hex()
            hex_info_serial_number = info_serial_number.hex()
            hex_error_check = error_check.hex()
            hex_end_bit = end_bit.hex()

            print(f"Start Bit: {hex_start_bit}")
            print(f"Length: {hex_length}")
            print(f"Information Serial Number: {hex_info_serial_number}")
            print(f"Error Check: {hex_error_check}")
            print(f"End Bit: {hex_end_bit}")

            # Processa com base no número de protocolo (no exemplo, é o campo info_serial_number)
            protocol_number = hex_info_serial_number
            if protocol_number == '0102':  # Exemplo: protocolo específico
                response = self.decode_data(packet)
            else:
                response = f"Protocolo desconhecido: {protocol_number}"

            return response
        except Exception as e:
            return f"Erro ao processar o pacote: {e}"

    def decode_data(self, packet):
        # Implementar a lógica de decodificação específica
        # Exemplo: retornar o conteúdo do pacote como uma string
        return f"Dados decodificados: {packet.hex()}"

if __name__ == "__main__":
    server = Server()
    server.start()
