import socket
import logging
import signal
import sys

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

setup_logging()

def parse_hex_strings(hex_string):
    hex_string = hex_string.lower().replace(" ", "")
    
    if len(hex_string) % 2 != 0:
        raise ValueError("A string Hex tem que ter um número de dígitos específico")
    
    byte_array = bytearray.fromhex(hex_string)
    
    packet_length = int(byte_array[2])
    
    if len(byte_array) < packet_length + 5:
        raise ValueError(f"Comprimento incorreto do pacote. Esperado {packet_length + 5} bytes, mas recebeu {len(byte_array)} bytes.")

    protocol_number = byte_array[3]
    
    common_fields = {
    "Start bit": translate_to_ascii(byte_array[:2]),
    "Packet Length": f"{packet_length} bytes",
    "Protocol Number": f"{protocol_number:02X}",

}
  
    specific_fields = {}

    if protocol_number == 0x01:
        specific_fields = extract_protocol_01_fields(byte_array)
    elif protocol_number == 0x17:
        specific_fields = extract_protocol_17_fields(byte_array)
    else:
        raise ValueError(f"Pacote Desconhecido com Protocolo {protocol_number}. Suporta apenas pacotes 0x01 e 0x17.")

    common_fields.update(specific_fields)
    return common_fields


def translate_to_ascii(byte_array):
    return byte_array.hex().upper()

def extract_protocol_01_fields(byte_array):
    device_id = byte_array[4:12].hex().upper()
    information_serial_number = int.from_bytes(byte_array[12:14], byteorder='big')
    error_check = int.from_bytes(byte_array[14:16], byteorder='big')
    end_bit = byte_array[16:18].hex().upper()

    translated_data = {
        "Device ID": f"{device_id[:2]}:{device_id[2:4]}:{device_id[4:6]}:{device_id[6:8]}:{device_id[8:10]}:{device_id[10:12]}",
        "Information Serial Number": information_serial_number,
        "Error Check": error_check,
        "End Bit": end_bit,
    }
    
    return translated_data


def bytes_to_latitude(byte_value):
    """Converts a byte array representing latitude to a decimal value."""
    integer_value = int.from_bytes(byte_value, byteorder='big')
    scaled_value = integer_value / 30000
    latitude_decimal = scaled_value / 60

    if byte_value[0] & 0x80: 
        latitude_decimal *= -1 

    return latitude_decimal

def bytes_to_longitude(byte_value):
    """Converts a byte array representing longitude to a decimal value."""
    integer_value = int.from_bytes(byte_value, byteorder='big')
    scaled_value = integer_value / 30000
    longitude_decimal = scaled_value / 60

    if byte_value[0] & 0x80: 
        longitude_decimal *= -1 
        
    return longitude_decimal

def parse_course_status(course_status_bytes):
    course_status = int.from_bytes(course_status_bytes, byteorder='big')

    reserved = (course_status >> 7) & 1
    din_status = (course_status >> 6) & 1
    gps_positioning_type = (course_status >> 5) & 1 
    gps_positioned = (course_status >> 4) & 1  
    longitude_direction = 'East' if (course_status >> 3) & 1 == 0 else 'West'
    latitude_direction = 'North' if (course_status >> 2) & 1 == 0 else 'South'

    course = course_status & 0x03

    return {
        "Reserved": reserved,
        "Din Status": din_status,
        "GPS Positioning Type": 'Real-time' if gps_positioning_type == 0 else 'Differential',
        "GPS Positioned": 'Not Positioned' if gps_positioned == 0 else 'Positioned',
        "Longitude Direction": longitude_direction,
        "Latitude Direction": latitude_direction,
        "Course": course
    }


# Mapeamento de MCC para países
mcc_country_mapping = {
    "724": "Brasil",
    "310": "Estados Unidos",
    "234": "Reino Unido",
    "460": "China",
    # Adicione mais MCCs conforme necessário
}

# Mapeamento de MCC + MNC para operadoras
mnc_mapping = {
    "724": {  # Brasil
        "02": "TIM",
        "03": "Claro",
        "04": "Vivo",
        "10": "Oi"
    },
    "310": {  # Estados Unidos
        "260": "T-Mobile",
        "410": "AT&T",
        "150": "Verizon"
    },
    "234": {  # Reino Unido
        "10": "O2",
        "15": "Vodafone",
        "30": "EE"
    },
    # Adicione mais MNCs conforme necessário
}

def get_country_from_mcc(mcc):
    """Retorna o país associado ao MCC."""
    mcc_str = str(mcc)
    return mcc_country_mapping.get(mcc_str, "País Desconhecido")

def get_operator_from_mcc_mnc(mcc, mnc):
    """Retorna a operadora associada ao MCC + MNC."""
    mcc_str = str(mcc)
    mnc_str = f"{mnc:02X}"  # Converte o MNC para string hexadecimal com dois dígitos
    if mcc_str in mnc_mapping:
        return mnc_mapping[mcc_str].get(mnc_str, "Operadora Desconhecida")
    return "Operadora Desconhecida"


def extract_protocol_17_fields(byte_array):
    date_time = byte_array[4:10]
    formatted_date_time = translate_date_time(date_time)

    latitude = bytes_to_latitude(byte_array[11:15])
    longitude = bytes_to_longitude(byte_array[15:19])

    specific_fields = {
        "GPS Information": {   
            "Date Time": formatted_date_time,
            "Quantity of GPS Satellites": byte_array[10],
            "Latitude": latitude,
            "Longitude": longitude,
            "Speed": f"{int.from_bytes(byte_array[19:21], byteorder='big')} km/h",
            "Course Status": parse_course_status(byte_array[20:22])
        },
        "LBS Information": {            
            "MCC": int.from_bytes(byte_array[22:24], byteorder='big'),
            "MNC": byte_array[24],
            "LAC": int.from_bytes(byte_array[25:27], byteorder='big'),
            "Cell ID": int.from_bytes(byte_array[27:30], byteorder='big'),
        },
        "Status Information": {
            "Device Status": "Active" if byte_array[30] & 0x01 else "Inactive",  # Exemplo de status do dispositivo
            "Battery Voltage Level": byte_array[31],
            "GSM Signal Strength": byte_array[32],
            "Battery Voltage": byte_array[33:35].hex().upper(),
            "External Voltage": byte_array[35:37].hex().upper(),
        },
        "Mileage": byte_array[37:41].hex().upper(),
        "Hourmeter": byte_array[41:45].hex().upper(),
        "Information Serial Number": byte_array[45:47].hex().upper(),
        "Error Check": byte_array[47:49].hex().upper(),
        "End Bit": byte_array[49:51].hex().upper(),
    }
    return specific_fields





def translate_date_time(byte_array):
    year = byte_array[0] % 100
    month = byte_array[1]
    day = byte_array[2]
    hour = byte_array[3]
    minute = byte_array[4]
    second = byte_array[5]
    
    return f"{year:02d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"




def handle_error(e, addr):
    logging.error(f"Erro de conexão com {addr}: {e}")

def send_response(conn, message):
    conn.sendall(message.encode('utf-8'))

def signal_handler(sig, frame):
    print("Interrompendo o servidor...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start_server(host='localhost', port=5050):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()

        print(f"Servidor escutando em {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            print(f"Conexão estabelecida com {addr}")
            
            while True:
                try:
                    data = conn.recv(1024)
                    if not data:
                        print(f"Conexão encerrada por {addr}")
                        break

                    hex_string = data.hex().upper()

                    print(f"Pacote recebido (em bytes): {len(data)}")

                    try:
                        parsed_packet = parse_hex_strings(hex_string)
                        print("Pacote Analisado:", parsed_packet)
                        send_response(conn, "Pacote processado com sucesso.")
                    except ValueError as e:
                        handle_error(e, addr)

                except ConnectionResetError:
                    print(f"Conexão foi resetada por {addr}")
                    break

if __name__ == "__main__":
    start_server()
