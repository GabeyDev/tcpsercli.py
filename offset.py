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
    
    # Modificando para calcular o comprimento total do pacote de forma flexível
    packet_length = byte_array[2] + 5  # Start bit (2) + Length (1) + Protocol Number (1) + Dados + Error Check (2) + End Bit (2)
    
    if len(byte_array) < packet_length:
        raise ValueError(f"Comprimento incorreto do pacote. Esperado {packet_length} bytes, mas recebeu {len(byte_array)} bytes.")

    protocol_number = byte_array[3]
    
    common_fields = {
        "Start bit": translate_to_ascii(byte_array[:2]),
        "Packet Length": f"{packet_length} bytes",
        "Protocol Number": f"{protocol_number:02X}",
    }
  
    specific_fields = {}

    if protocol_number == 0x01:
        specific_fields = extract_protocol_fields(byte_array, 0x01)
    elif protocol_number == 0x17:
        specific_fields = extract_protocol_fields(byte_array, 0x17)
    else:
        raise ValueError(f"Pacote Desconhecido com Protocolo {protocol_number}. Suporta apenas pacotes 0x01 e 0x17.")

    common_fields.update(specific_fields)
    return common_fields

def translate_to_ascii(byte_array):
    return byte_array.hex().upper()

def extract_protocol_fields(byte_array, protocol_number):
    if protocol_number == 0x01:
        return extract_protocol_01_fields(byte_array)
    elif protocol_number == 0x17:
        return extract_protocol_17_fields(byte_array)
    else:
        raise ValueError("Protocolo não suportado.")

def extract_protocol_01_fields(byte_array):
    device_id = byte_array[4:12].hex().upper()
    information_serial_number = int.from_bytes(byte_array[12:14], byteorder='big')
    error_check = int.from_bytes(byte_array[14:16], byteorder='big')
    end_bit = byte_array[16:18].hex().upper()

    return {
        "Device ID": f"{device_id[:2]}:{device_id[2:4]}:{device_id[4:6]}:{device_id[6:8]}:{device_id[8:10]}:{device_id[10:12]}",
        "Information Serial Number": information_serial_number,
        "Error Check": error_check,
        "End Bit": end_bit,
    }

def extract_protocol_17_fields(byte_array):
    current_offset = 4

    date_time = byte_array[current_offset:current_offset + 6]
    formatted_date_time = translate_date_time(date_time)
    current_offset += 6

    quantity_of_gps_sats = byte_array[current_offset]
    current_offset += 1

    latitude = bytes_to_latitude(byte_array[current_offset:current_offset + 4])
    current_offset += 4

    longitude = bytes_to_longitude(byte_array[current_offset:current_offset + 4])
    current_offset += 4

    speed = int.from_bytes(byte_array[current_offset:current_offset + 2], byteorder='big')
    current_offset += 2

    course_status = parse_course_status(byte_array[current_offset:current_offset + 2])
    current_offset += 2

    mcc = int.from_bytes(byte_array[current_offset:current_offset + 2], byteorder='big')
    current_offset += 2

    mnc = byte_array[current_offset]
    current_offset += 1

    lac = int.from_bytes(byte_array[current_offset:current_offset + 2], byteorder='big')
    current_offset += 2

    cell_id = int.from_bytes(byte_array[current_offset:current_offset + 3], byteorder='big')
    current_offset += 3

    status_info = byte_array[current_offset:current_offset + 5]
    current_offset += 5

    mileage = int.from_bytes(byte_array[current_offset:current_offset + 4], byteorder='big', signed=False)
    current_offset += 4

    hourmeter = int.from_bytes(byte_array[current_offset:current_offset + 4], byteorder='big', signed=False)
    current_offset += 4

    information_serial_number = int.from_bytes(byte_array[current_offset:current_offset + 2], byteorder='big', signed=False)
    current_offset += 2

    error_check = int.from_bytes(byte_array[current_offset:current_offset + 2], byteorder='big', signed=False)
    current_offset += 2

    end_bit = byte_array[current_offset:current_offset + 2].hex().upper()

    return {
        "GPS Information": {
            "Date Time": formatted_date_time,
            "Quantity of GPS Satellites": quantity_of_gps_sats,
            "Latitude": latitude,
            "Longitude": longitude,
            "Speed": f"{speed} km/h",
            "Course Status": course_status
        },
        "LBS Information": {
            "MCC": f"{mcc} - {get_country_from_mcc(mcc)}",
            "MNC": f"{mnc} - {get_operator_from_mcc_mnc(mcc, mnc)}",
            "LAC": lac,
            "Cell ID": cell_id,
        },
        "Status Information": {
            "Device Status": "Active" if status_info[0] & 0x01 else "Inactive",
            "Battery Voltage Level": parse_battery_voltage_level(status_info[1:2]),
            "GSM Signal Strength": parse_gsm_signal_strength(status_info[2]),
            "Battery Voltage": parse_battery_voltage(status_info[3:5]),
            "External Voltage": parse_external_voltage(status_info[5:7]),
        },
        "Mileage": f"{mileage} m",
        "Hourmeter": parse_hourmeter(byte_array[current_offset-4:current_offset]),
        "Information Serial Number": information_serial_number,
        "Error Check": error_check,
        "End Bit": end_bit,
    }

def translate_date_time(byte_array):
    year = byte_array[0] + 2000
    month = byte_array[1]
    day = byte_array[2]
    hour = byte_array[3]
    minute = byte_array[4]
    second = byte_array[5]
    
    return f"{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"

def bytes_to_latitude(byte_value):
    integer_value = int.from_bytes(byte_value, byteorder='big')
    scaled_value = integer_value / 30000
    latitude_decimal = scaled_value / 60

    if byte_value[0] & 0x80: 
        latitude_decimal *= -1 

    return latitude_decimal

def bytes_to_longitude(byte_value):
    integer_value = int.from_bytes(byte_value, byteorder='big')
    scaled_value = integer_value / 30000
    longitude_decimal = scaled_value / 60

    if byte_value[0] & 0x80: 
        longitude_decimal *= -1 
        
    return longitude_decimal

def parse_course_status(byte_array):
    reserved = (byte_array[0] >> 7) & 0x01
    din_status = (byte_array[0] >> 6) & 0x01
    gps_real_time = (byte_array[0] >> 5) & 0x01
    gps_positioned = (byte_array[0] >> 4) & 0x01
    east_longitude = (byte_array[0] >> 3) & 0x01
    south_latitude = (byte_array[0] >> 2) & 0x01
    course = byte_array[1]

    return {
        "Reserved": reserved,
        "Din Status": din_status,
        "GPS Real-Time": gps_real_time,
        "GPS Positioned": gps_positioned,
        "East Longitude": east_longitude,
        "South Latitude": south_latitude,
        "Course": course
    }

def parse_mcc(mcc_bytes):
    mcc_value = int.from_bytes(mcc_bytes, byteorder='big')
    return mcc_value

def get_country_from_mcc(mcc):
    mcc_table = {
        724: "Turquia",
        356: "Índia",
    }
    return mcc_table.get(mcc, "Código MCC não encontrado")

def get_operator_from_mcc_mnc(mcc, mnc):
    operator_mapping = {
        (724, 1): "NOS",      
        (724, 2): "Vodafone", 
        (276, 1): "T-Mobile", 
        (310, 26): "AT&T",
    }
    return operator_mapping.get((mcc, mnc), "Desconhecido")

def parse_battery_voltage_level(byte_array):
    level = byte_array[0]
    return {
        0: "Menor energia e desligado",
        1: "Energia insuficiente para chamadas ou mensagens",
        2: "Baixa energia e alarme",
        3: "Baixa energia, mas funciona normalmente",
        4: "Boa condição",
        5: "Excelente condição",
    }.get(level, "Desconhecido")

def parse_gsm_signal_strength(signal_strength):
    return (signal_strength / 2) * 100

def parse_battery_voltage(byte_array):
    return int.from_bytes(byte_array, byteorder='big') / 1000

def parse_external_voltage(byte_array):
    return int.from_bytes(byte_array, byteorder='big') / 1000

def receive_data(byte_array):
    hourmeter_start_index = ()
    hourmeter_end_index = hourmeter_start_index + 4

    hourmeter_bytes = byte_array[hourmeter_start_index:hourmeter_end_index]

    if len(hourmeter_bytes) < 4:
        print("Erro: Dados do hourmeter não estão completos.")
        return

    print(f"Bytes do hourmeter recebidos: {hourmeter_bytes.hex()}")

    total_seconds = int.from_bytes(hourmeter_bytes, byteorder='big')
    print(f"Valor do hourmeter em segundos: {total_seconds}")

    formatted_hourmeter = parse_hourmeter(hourmeter_bytes)
    print(formatted_hourmeter)


def parse_hourmeter(byte_array):
    total_seconds = int.from_bytes(byte_array, byteorder='big')
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours}h {minutes}m {seconds}s"



def main():
    signal.signal(signal.SIGINT, signal_handler)
    host = '0.0.0.0'
    port = 5050

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        logging.info(f"Servidor TCP em execução em {host}:{port}")

        while True:
            conn, addr = s.accept()
            with conn:
                logging.info(f"Conexão recebida de {addr}")
                data = conn.recv(1024)
                if data:
                    try:
                        logging.info("Recebido: %s", data.hex().upper())
                        result = parse_hex_strings(data.hex())
                        logging.info("Resultado: %s", result)
                    except ValueError as e:
                        logging.error("Erro ao processar dados: %s", e)

def signal_handler(sig, frame):
    logging.info("Encerrando o servidor...")
    sys.exit(0)

if __name__ == "__main__":
    main()
