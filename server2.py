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
        "Information Serial Number": byte_array[13:15].hex(),
        "Error Check": byte_array[16:18].hex(),
        "End Bit": byte_array[19:21].hex()
    }
    
    specific_field = {}
    
    # Login
    if protocol_number == 0x01:
        specific_field = {
            "Device ID": byte_array[4:12].hex()
        }
    else:
        raise ValueError("PAcote desconhecido.")
    
    common_fields.update(specific_field)
    return common_fields
