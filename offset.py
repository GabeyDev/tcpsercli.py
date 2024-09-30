import socket
import logging
import signal
import sys
import threading
import logging
import traceback


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

def validate_packet_content(byte_array):
    if not all(0 <= byte <= 255 for byte in byte_array):
        raise ValueError("Conteúdo do pacote contém bytes fora do intervalo esperado (0-255).")


def translate_to_ascii(byte_array):
    return byte_array.hex().upper()

def extract_protocol_01_fields(byte_array):
    if len(byte_array) < 18:
        raise ValueError("Pacote muito curto para o protocolo 0x01.")
    
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

def test_bytes_to_latitude():
    assert bytes_to_latitude(bytearray([0x00, 0x00, 0x00, 0x01])) == 0.000005555555555555556
    
def test_bytes_to_longitude():
    assert bytes_to_longitude(bytearray([0x00, 0x00, 0x00, 0x01])) == 0.000005555555555555556


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
        "GPS Positioning Type": 'Tempo-Real' if gps_positioning_type == 0 else 'Diferencial',
        "GPS Positioned": 'Não Posicionado' if gps_positioned == 0 else 'Posicionado',
        "Longitude Direction": longitude_direction,
        "Latitude Direction": latitude_direction,
        "Course": course
    }

mcc_country_mapping = {
    "724": "Brasil",
    "310": "Estados Unidos",
    "234": "Reino Unido",
    "460": "China",
}

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
}

def get_country_from_mcc(mcc):
    mcc_str = str(mcc)
    return mcc_country_mapping.get(mcc_str, "País Desconhecido")

def get_operator_from_mcc_mnc(mcc, mnc):
    mcc_str = str(mcc)
    mnc_str = f"{mnc:02X}"
    if mcc_str in mnc_mapping:
        return mnc_mapping[mcc_str].get(mnc_str, "Operadora Desconhecida")
    return "Operadora Desconhecida"

def interpret_battery_voltage(level):
    if level == 0:
        return "Lowest power and power off"
    elif level == 1:
        return "Not enough power to dial a call or send messages."
    elif level == 2:
        return "Low power and alarm"
    elif level == 3:
        return "Lower power but can work normally"
    elif 3 < level <= 6:
        return "Work in good condition"
    else:
        return "Unknown battery level"

def external_voltage_to_bytes(voltage):
    voltage_int = int(voltage * 100)

    if voltage_int > 65535:
        voltage_int = 65535

    return voltage_int.to_bytes(2, byteorder='big')

import datetime

def seconds_to_hms(seconds):
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}h {minutes}m {seconds}s"

def extract_protocol_17_fields(byte_array):
    if len(byte_array) < 50: 
        raise ValueError("Pacote muito curto para o protocolo 0x17.")
    
    try:
        date_time = byte_array[4:10]
        formatted_date_time = translate_date_time(date_time)

        latitude = bytes_to_latitude(byte_array[11:15])
        longitude = bytes_to_longitude(byte_array[15:19])

        mcc = int.from_bytes(byte_array[22:24], byteorder='big')
        mnc = byte_array[24]

        battery_voltage_level = byte_array[31]
        battery_voltage_description = interpret_battery_voltage(battery_voltage_level)

        battery_voltage_raw = int.from_bytes(byte_array[33:35], byteorder='big')
        battery_voltage_value = battery_voltage_raw / 100 

        external_voltage_raw = int.from_bytes(byte_array[35:37], byteorder='big')
        external_voltage_value = external_voltage_raw / 100

        mileage = int.from_bytes(byte_array[37:41], byteorder='big', signed=False)

        hourmeter_seconds = int.from_bytes(byte_array[41:45], byteorder='big', signed=False)
        hourmeter_formatted = seconds_to_hms(hourmeter_seconds)

        information_serial_number = int.from_bytes(byte_array[45:47], byteorder='big', signed=False)

        error_check = byte_array[47:49].hex().upper()

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
                "MCC": mcc,
                "Country": get_country_from_mcc(mcc),
                "MNC": mnc,
                "Operator": get_operator_from_mcc_mnc(mcc, mnc),
                "LAC": int.from_bytes(byte_array[25:27], byteorder='big'),
                "Cell ID": int.from_bytes(byte_array[27:30], byteorder='big'),
            },
            "Status Information": {
                "Device Status": "Active" if byte_array[30] & 0x01 else "Inactive",
                "Battery Voltage Level": f"{battery_voltage_level} - {battery_voltage_description}",
                "GSM Signal Strength": f"{byte_array[32]}%", 
                "Battery Voltage": f"{battery_voltage_value:.2f}V",
                "External Voltage": f"{external_voltage_value:.2f}V",
            },
            "Mileage": f"{mileage} meters",
            "Hourmeter": hourmeter_formatted,
            "Information Serial Number": information_serial_number,
            "Error Check": error_check,
            "End Bit": byte_array[49:51].hex().upper(),
        }
        
        return specific_fields
    except Exception as e:
        logging.error(f"Erro ao extrair campos do protocolo 0x17: {e}")
        raise


def calculate_checksum(byte_array):
    checksum = 0
    for b in byte_array:
        checksum ^= b
    return checksum.to_bytes(2, byteorder='big')

def create_ack_packet(protocol_number, information_serial_number):
    start_bit = bytearray.fromhex("7878")
    length = bytearray([0x05])
    protocol_num = bytearray([protocol_number])
    info_serial_num = information_serial_number.to_bytes(2, byteorder='big')
    packet_without_error_check = length + protocol_num + info_serial_num
    error_check = calculate_checksum(packet_without_error_check)
    end_bit = bytearray.fromhex("0D0A")
    ack_packet = start_bit + packet_without_error_check + error_check + end_bit
    return ack_packet

def parse_ack_packet(data):
    if len(data) < 10:
        raise ValueError("Pacote ACK muito curto.")

    start_bit = data[:2]
    length = data[2]
    protocol_number = data[3]
    information_serial_number = int.from_bytes(data[4:6], byteorder='big')
    received_crc = data[6:8]
    end_bit = data[8:]

    if start_bit != bytearray.fromhex("7878"):
        raise ValueError("Start Bit inválido.")
    if end_bit != bytearray.fromhex("0D0A"):
        raise ValueError("End Bit inválido.")

    expected_length = length + 5
    if len(data) != expected_length + 2:
        raise ValueError(f"Comprimento do pacote inválido. Esperado {expected_length + 2}, mas recebeu {len(data)}.")

    packet_without_error_check = data[:6]
    calculated_error_check = calculate_checksum(packet_without_error_check)

    if received_crc != calculated_error_check:
        raise ValueError("Checksum inválido.")

    return {
        "Protocol Number": protocol_number,
        "Information Serial Number": information_serial_number
    }


def send_ack_response(conn, protocol_number, information_serial_number):
    ack_packet = create_ack_packet(protocol_number, information_serial_number)
    conn.sendall(ack_packet)
    print(f"ACK enviado: {ack_packet.hex().upper()}")

def translate_date_time(byte_array):
    year = byte_array[0] % 100
    month = byte_array[1]
    day = byte_array[2]
    hour = byte_array[3]
    minute = byte_array[4]
    second = byte_array[5]
    return f"{year:02d}-{month:02d}-{day:02d} {hour:02d}:{minute:02d}:{second:02d}"

def handle_error(e, data):
    logging.error(f"Erro ao processar dados: {data.hex().upper()}")

def processar_pacote(data, conn):
    try:
        if not isinstance(data, bytearray):
            raise ValueError("Os dados devem ser um bytearray.")

        start_bit = data[:2]
        length = data[2]
        protocol_number = data[3]
        information_serial_number = int.from_bytes(data[4:6], byteorder='big')
        
        # Validate the start bit
        if start_bit != bytearray.fromhex("7878"):
            raise ValueError("Start Bit inválido.")

        # Process the packet based on its protocol
        common_fields = parse_hex_strings(data.hex())
        logging.info(f"Pacote processado: {common_fields}")

        # Send an acknowledgment response
        send_ack_response(conn, protocol_number, information_serial_number)

    except Exception as e:
        handle_error(e, data)

def start_server(host='0.0.0.0', port=5050):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    logging.info(f"Servidor escutando em {host}:{port}")

    while True:
        try:
            conn, addr = server_socket.accept()
            logging.info(f"Conexão estabelecida com {addr}")
            thread = threading.Thread(target=handle_client, args=(conn,))
            thread.start()
        except KeyboardInterrupt:
            logging.info("Servidor interrompido.")
            break
    server_socket.close()

def handle_client(conn):
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            processar_pacote(bytearray(data), conn)

if __name__ == "__main__":
    start_server()


def processar_resposta_servidor(data):
    start_bit = data[:4]
    length = int(data[4:6], 16)
    protocol_number = data[6:8]
    serial_number = data[8:12]
    error_check = data[12:16]
    end_bit = data[16:] 

    logging.info(f"Resposta do servidor decodificada: Start Bit: {start_bit}, "
                 f"Length: {length}, Protocol Number: {protocol_number}, "
                 f"Serial Number: {serial_number}, Error Check: {error_check}, End Bit: {end_bit}")

def processar_dados_dispositivo(data):
    pass


def send_response(conn, message):
    conn.sendall(message.encode('utf-8'))

def signal_handler(sig, frame):
    print("Interrompendo o servidor...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


def handle_client_connection(conn, addr):
    try:
        logging.info(f"Conexão estabelecida com {addr}")
        while True:
            data = conn.recv(1024)
            if not data:
                logging.info(f"Conexão encerrada por {addr}")
                break

            try:
                logging.info(f"Dados recebidos de {addr}: {data.hex().upper()}")
                parsed_data = parse_hex_strings(data.hex())
                logging.info(f"Dados decodificados: {parsed_data}")
                
                protocol_number = int(parsed_data["Protocol Number"], 16)
                information_serial_number = parsed_data.get("Information Serial Number", 0)
                send_ack_response(conn, protocol_number, information_serial_number)
            
            except ValueError as e:
                handle_error(e, data)

    except Exception as e:
        logging.error(f"Erro na conexão com {addr}: {e}")

    finally:
        conn.close()


def start_server(host="0.0.0.0", port=5050):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((host, port))
        server_socket.listen(5)
        logging.info(f"Servidor TCP iniciado em {host}:{port}")

        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client_connection, args=(conn, addr))
            client_thread.start()


if __name__ == "__main__":
    try:
        start_server()
    except Exception as e:
        logging.error(f"Erro ao iniciar o servidor: {e}")
    except KeyboardInterrupt:
        logging.info("Servidor interrompido.")
