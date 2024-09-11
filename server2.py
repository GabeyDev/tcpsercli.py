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

            if decode_func:
            response = decode_func(device_id, information_serial_number, error_check)   
            else:
            response = f"Protocolo desconhecido: {protocol_number}"

            return response
        
        except Exception as e:
            return f"Erro ao processar o pacote: {e}"
        
        
    def decode_protocol_01(self, device_id, information_serial_number, error_check):
        # Decodificação para o protocolo 01 (exemplo: data YYYYMMDD)
        year = int(information_serial_number[:4], 16)
        month = int(information_serial_number[4:6], 16)
        day = int(information_serial_number[6:8], 16)
        return {'device_id': device_id, 'date': f"{year}-{month:02d}-{day:02d}"}

    def decode_protocol_02(self, device_id, information_serial_number, error_check):
        # Decodificação para o protocolo 02 (exemplo: temperatura em Celsius)
        temperature_bytes = bytes.fromhex(information_serial_number)
        temperature = struct.unpack('>h', temperature_bytes)[0] / 100.0
        return {'device_id': device_id, 'temperature': temperature}

    def decode_protocol_03(self, device_id, information_serial_number, error_check):
        # Decodificação para o protocolo 03 (exemplo: string de 16 caracteres)
        string_bytes = bytes.fromhex(information_serial_number)
        string = string_bytes.decode('utf-8')
        return {'device_id': device_id, 'string': string}   
    def decode_protocol_04(self, buffer):
        try

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
