def parse_hex_strings(hex_string):
    # Remove espaços e converte para minúsculas
    hex_string = hex_string.lower().replace(" ", "")

    if len(hex_string) % 2 != 0:
        print("Comprimento ímpar detectado. Adicionando um zero no início para corrigir.")
        hex_string = '0' + hex_string
    
    try:
        byte_array = bytearray.fromhex(hex_string)
    except ValueError:
        raise ValueError("Erro ao converter a string hex. Verifique se todos os caracteres são válidos.")
    
    packet_length = byte_array[2]

    if len(byte_array) < packet_length + 5:
        print(f"Atenção: O pacote recebido é menor do que o esperado ({packet_length + 5} bytes), mas será processado.")
    elif len(byte_array) > packet_length + 5:
        print(f"Atenção: O pacote recebido é maior do que o esperado ({packet_length + 5} bytes), mas será processado.")

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
        gps_info = {
            "Date Time": byte_array[4:10].hex(),
            "Quantity of GPS satellites": f"0x{byte_array[10]:02X}",
            "Latitude": byte_array[11:15].hex(),
            "Longitude": byte_array[15:19].hex(),
            "Speed": f"0x{byte_array[19]:02X}",
            "Course Status": byte_array[20:22].hex(),
        }
        
        specific_fields = {
            "GPS information": gps_info,
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

def main():
    while True:
        hex_string = input("Cole o Pacote aqui (ou digite 'sair' para fechar o terminal): ").strip()
        if hex_string.lower() == "sair":
            break
        try:
            parsed_packet = parse_hex_strings(hex_string)
            print("Pacote Analisado:", parsed_packet)
        except ValueError as e:
            print(f"Erro: {e}")

if __name__ == "__main__":
    main()
