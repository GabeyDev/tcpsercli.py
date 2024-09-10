import socket
import threading

class Packet:
    """Classe base para pacotes, contendo métodos comuns de decodificação."""
    def __init__(self, buffer):
        self.buffer = buffer
        self.start_bit = buffer[:2].hex()
        self.length = buffer[2:3].hex()
        self.protocol_number = buffer[3:4].hex()

class DevicePacket(Packet):
    """Classe para pacotes enviados do dispositivo (protocol_number 01)."""
    def __init__(self, buffer):
        super().__init__(buffer)
        self.device_id = buffer[4:12].hex()
        self.information_serial_number = buffer[12:14].hex()
        self.error_check = buffer[14:16].hex()
        self.end_bit = buffer[16:18].hex()

    def decode(self):
        decoded_message = (
            f"Decodificação do Pacote do Dispositivo:\n"
            f"Start Bit: {self.start_bit}\n"
            f"Length: {self.length}\n"
            f"Protocol Number: {self.protocol_number}\n"
            f"Device ID: {self.device_id}\n"
            f"Information Serial Number: {self.information_serial_number}\n"
            f"Error Check: {self.error_check}\n"
            f"End Bit: {self.end_bit}"
        )
        return decoded_message

class ServerPacket(Packet):
    """Classe para pacotes enviados pelo servidor (protocol_number 02)."""
    def __init__(self, buffer):
        super().__init__(buffer)
        # GPS Information Group
        self.date_time = buffer[4:10].hex()
        self.gps_satellites = buffer[10:11].hex()
   
