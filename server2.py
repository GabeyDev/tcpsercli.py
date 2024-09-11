import socket
import threading
import binascii

class Packet:
    def __init__(self, buffer):
        self.buffer = buffer
        self.packet_type = buffer[0:1].hex() 
        self.start_bit = buffer[1:3].hex()
        self.length = buffer[3:4].hex()
        self.protocol_number = buffer[4:5].hex()


class DevicePacket(Packet):
    def __init__(self, buffer):
        super().__init__(buffer)
        offset = 4
        
        # GPS Information
        self.date_time = buffer[offset:offset+6].hex()
        offset += 6
        self.gps_quantity = buffer[offset:offset+1].hex()
        offset += 1
        self.latitude = buffer[offset:offset+4].hex()
        offset += 4
        self.longitude = buffer[offset:offset+4].hex()
        offset += 4
        self.speed = buffer[offset:offset+1].hex()
        offset += 1
        self.course_status = buffer[offset:offset+2].hex()
        offset += 2
        
        # LBS Information
        self.mcc = buffer[offset:offset+2].hex()
        offset += 2
        self.mnc = buffer[offset:offset+1].hex()
        offset += 1
        self.lac = buffer[offset:offset+2].hex()
        offset += 2
        self.cell_id = buffer[offset:offset+3].hex()
        offset += 3
        
        # Status Information
        self.device_info = buffer[offset:offset+1].hex()
        offset += 1
        self.battery_voltage_level = buffer[offset:offset+1].hex()
        offset += 1
        self.gsm_signal_strength = buffer[offset:offset+1].hex()
        offset += 1
        self.battery_voltage = buffer[offset:offset+2].hex()
        offset += 2
        self.external_voltage = buffer[offset:offset+2].hex()
        offset += 2
        
        # Outros campos
        self.mileage = buffer[offset:offset+4].hex()
        offset += 4
        self.hourmeter = buffer[offset:offset+4].hex()
        offset += 4
        self.information_serial_number = buffer[offset:offset+2].hex()
        offset += 2
        self.error_check = buffer[offset:offset+2].hex()
        offset += 2
        self.end_bit = buffer[offset:offset+2].hex()

    def decode(self):
        decoded_message = (
            f"Decodificação do Pacote do Dispositivo:\n"
            f"Start Bit: {self.start_bit}\n"
            f"Length: {self.length}\n"
            f"Protocol Number: {self.protocol_number}\n"
            f"Device Information: {self.device_info}\n"  # Ajustado aqui
            f"Information Serial Number: {self.information_serial_number}\n"
            f"Error Check: {self.error_check}\n"
            f"End Bit: {self.end_bit}"
        )
        return decoded_message

    def decode_detailed(self):
        detailed_message = (
            f"Decode 0x17\n"
            f"Start Bit: {self.start_bit}\n"
            f"Length: {self.length}\n"
            f"Protocol Number: {self.protocol_number}\n"
            
            f"GPS Information:\n"
            f"  Date Time: {self.date_time}\n"
            f"  Quantity of GPS Satellites: {self.gps_quantity}\n"
            f"  Latitude: {self.latitude}\n"
            f"  Longitude: {self.longitude}\n"
            f"  Speed: {self.speed}\n"
            f"  Course and Status: {self.course_status}\n"
            
            f"LBS Information:\n"
            f"  MCC: {self.mcc}\n"
            f"  MNC: {self.mnc}\n"
            f"  LAC: {self.lac}\n"
            f"  Cell ID: {self.cell_id}\n"
            
            f"Status Information:\n"
            f"  Device Information: {self.device_info}\n"
            f"  Battery Voltage Level: {self.battery_voltage_level}\n"
            f"  GSM Signal Strength: {self.gsm_signal_strength}\n"
            f"  Battery Voltage: {self.battery_voltage}\n"
            f"  External Voltage: {self.external_voltage}\n"
            
            f"Other Information:\n"
            f"  Mileage: {self.mileage}\n"
            f"  Hourmeter: {self.hourmeter}\n"
            f"  Information Serial Number: {self.information_serial_number}\n"
            f"  Error Check: {self.error_check}\n"
            f"  End Bit: {self.end_bit}"
        )
        return detailed_message

def handle_client(client_socket):
    while True:
        buffer = client_socket.recv(1024)
        if not buffer:
            break
        
        packet_type = buffer[0:1].hex()  # Identifica o tipo de pacote
        
        if packet_type == '01':
            # Processa o pacote com device ID
            print("Pacote com Device ID recebido")
            # Aqui você deve implementar a lógica para processar o pacote com Device ID
            # Exemplo fictício:
            device_id = buffer[1:].hex()
            print(f"Device ID: {device_id}")
        elif packet_type == '02':
            # Processa o pacote com informações detalhadas
            packet = DevicePacket(buffer)
            print("Mensagem Decodificada abaixo:")
            print(packet.decode())
            print("\nMensagem Decodificada abaixo:")
            print(packet.decode_detailed())
        else:
            print(f"Tipo de pacote desconhecido: {packet_type}")

    client_socket.close()


def start_server(host='127.0.0.1', port=5050):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"Servidor ouvindo na porta {port}")
    
    while True:
        client_socket, addr = server.accept()
        print(f"Conexão recebida de {addr}")
        client_handler = threading.Thread(target=handle_client, args=(client_socket,))
        client_handler.start()

if __name__ == "__main__":
    start_server()
