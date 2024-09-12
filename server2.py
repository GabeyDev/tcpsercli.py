import socket
import threading

class Server:
    def __init__(self, host='127.0.0.1', port=5050):
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

                while len(buffer) >= 5:  # Tamanho mínimo para começar a processar (2 bytes Start Bit + 1 byte Length)
                    length = buffer[2]  # O comprimento está na posição 2 (1 byte)
                    total_packet_length = 2 + 1 + length  # 2 bytes Start Bit + 1 byte Length + tamanho especificado

                    if len(buffer) < total_packet_length:
                        break  # Aguardando mais dados para um pacote completo

                    # Processa o pacote completo
                    packet = buffer[:total_packet_length]
                    response = self.process_packet(packet)
                    if response:
                        client_socket.sendall(response.encode())

                    # Remove o pacote processado do buffer
                    buffer = buffer[total_packet_length:]
            except Exception as e:
                print(f"Erro ao lidar com o cliente: {e}")
                break

        client_socket.close()
        print("Conexão fechada")

    def process_packet(self, packet):
        try:
            # Exemplo de estrutura de pacote
            start_bit = packet[:2].hex()
            length = packet[2]
            protocol_number = packet[3:4].hex()
            device_id = packet[4:12].hex()
            information_serial_number = packet[12:14].hex()
            error_check = packet[14:16].hex()
            end_bit = packet[16:18].hex()

            print(f"Start Bit: {start_bit}")
            print(f"Length: {length}")
            print(f"Protocol Number: {protocol_number}")
            print(f"Device ID: {device_id}")
            print(f"Information Serial Number: {information_serial_number}")
            print(f"Error Check: {error_check}")
            print(f"End Bit: {end_bit}")

            if protocol_number == '01':
                response = self.decode_protocol_01(device_id, information_serial_number, error_check)
            else:
                response = f"Protocolo desconhecido: {protocol_number}"

            return response
        except Exception as e:
            return f"Erro ao processar o pacote: {e}"

    def decode_protocol_01(self, device_id, information_serial_number, error_check):
        decoded_message = (
            f"Decodificação do dispositivo:\n"
            f"Device ID: {device_id}\n"
            f"Information Serial Number: {information_serial_number}\n"
            f"Error Check: {error_check}"
        )
        return decoded_message

if __name__ == "__main__":
    server = Server()
    server.start()
