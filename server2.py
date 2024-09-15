def parse_hex_strings(hex_string):
    hex_string = hex_string.lower().replace(" ", "")
    if len(hex_string) % 2 != 0:
        raise ValueError("A string Hex tem que ter um número de dígitos específico")
    
    byte_array = bytearray.fromhex(hex_string)
    protocol_number = byte_array[1]
    
    common_fields = {
        "Start bit": byte_array[:2].hex(),
        "Packet Length": f"0x{byte_array[2]:02X}",
        "Protocol Number": f"0x{protocol_number:02X}",
    }
    
    specific_fields = {}
    
    if protocol_number == 0x01:
        specific_field = {
            "Device ID": byte_array[4:12].hex()
            "Information Serial Number": byte_array[13:15].hex(), # type: ignore
            "Error Check": byte_array[16:18].hex(),
            "End Bit": byte_array[19:21].hex()
        }
        
    elif protocol_number == 0x17:
            specific_fields = {
            "GPS information" : {   
                "Date Time": byte_array[4:10].hex(),
                "Quantity of GPS satellites": f"0x{byte_array[10]:02X}",
                "Latitude": byte_array[11:15].hex(),
                "Longitude": byte_array[15:19].hex(),
                "Speed": f"0x{byte_array[19]:02X}",
                "Course Status": byte_array[20:22].hex()
            },
            "LBS Information":  {            
                "MCC": f"0x{byte_array[22:24]:02X}",
                "MNC": byte_array[25].hex(),
                "LAC": f"0x{byte_array[25:27].hex()}",
                "Cell ID": byte_array[26:29].hex(),
            },
            "Status Information": {
                "Device Information": f"0x{byte_array[30]:02X}",
                "Battery Voltage Level": f"0x{byte_array[31]:02X}",
                "GSM Signal Strength": f"0x{byte_array[32]:02X}",
                "Battery Voltage": byte_array[33:35].hex(),
                "External Voltage": byte_array[36:38].hex()
            },
            "Mileage": byte_array[39:43].hex(),
            "Horimeter": byte_array[44:48].hex(),
            "Information Serial Number": byte_array[48:50].hex(),
            "Error Check": byte_array[50:52].hex(),
            "End Bit": byte_array[52:].hex(),
        } 
              
    else:
        raise ValueError("Pacote Desconhecido. Suporta apenas pacotes 0x01, 0x17, 0x13, 0x16, 0x094 e 0x80.")

    common_fields.update(specific_fields)
    parse_packet = {**common_fields}

    return parse_packet
