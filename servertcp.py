import socket

def parse_hex_strings(hex_string):
    hex_string = hex_string.lower().replace(" ", "")
    
    if len(hex_string) % 2 != 0:
        raise ValueError("A string Hex tem que ter um número de dígitos específico")
    
    byte_array = bytearray.fromhex(hex_string)
    
    packet_length = byte_array[2]
    if len(byte_array) != packet_length + 5:
        raise ValueError(f"Comprimento incorreto do pacote. Esperado {packet_length + 5} bytes, mas recebeu {len(byte_array)} bytes.")
    
    protocol_number = byte_array[3]
    
    common_fields = {
        "Start bit": byte_array[:2].hex(),
        "Packet Length": f"0x{packet_length:02X}",
        "Protocol Number": f"0x{protocol_number:02X}",
    }
    
    specific_fields = {}
    
    if protocol_number == 0x01:
        specific_fields = {
            "Device ID": byte_array[4:12].hex(),
            "Serial Number": byte_array[12:14].hex(),
            "Error Check": byte_array[14:16].hex(),
            "End Bit": byte_array[16:18].hex()
        }
        
    elif protocol_number == 0x17:
        specific_fields = {
            "GPS information": {   
                "Date Time": byte_array[4:10].hex(),
                "Quantity of GPS satellites": f"0x{byte_array[10]:02X}",
                "Latitude": byte_array[11:15].hex(),
                "Longitude": byte_array[15:19].hex(),
                "Speed": f"0x{byte_array[19]:02X}",
                "Course Status": byte_array[20:22].hex()
            },
            "LBS Information": {            
                "MCC": byte_array[22:24].hex(),
                "MNC": f"0x{byte_array[24]:02X}",
                "LAC": byte_array[25:27].hex(),
                "Cell ID": byte_array[27:30].hex(),
            },
            "Status Information": {
                "Device Information": f"0x{byte_array[30]:02X}",
                "Battery Voltage Level": f"0x{byte_array[31]:02X}",
                "GSM Signal Strength": f"0x{byte_array[32]:02X}",
                "Battery Voltage": byte_array[33:35].hex(),
                "External Voltage": byte_array[35:37].hex()
            },
            "Mileage": byte_array[37:41].hex(),
            "Hourmeter": byte_array[41:45].hex(),
            "Information Serial Number": byte_array[45:47].hex(),
            "Error Check": byte_array[47:49].hex(),
            "End Bit": byte_array[49:51].hex(),
        }
        
    else:
        raise ValueError(f"Pacote Desconhecido com Protocolo 0x{protocol_number:02X}. Suporta apenas pacotes 0x01 e 0x17.")

    # Combina campos comuns e específicos
    common_fields.update(specific_fields)
    return common_fields

def start_server(host='localhost', port=5050):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()

        print(f"Servidor escutando em {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            with conn:
                print(f"Conexão estabelecida com {addr}")

                data = conn.recv(1024)  # Recebe até 1024 bytes
                if not data:
                    break

                hex_string = data.hex().upper()
                print(f"Pacote recebido: {hex_string}")

                try:
                    parsed_packet = parse_hex_strings(hex_string)
                    print("Pacote Analisado:", parsed_packet)
                except ValueError as e:
                    print(f"Erro: {e}")

if __name__ == "__main__":
    start_server()
