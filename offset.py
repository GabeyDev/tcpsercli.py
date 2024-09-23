import socket
import logging
import signal
import sys

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

setup_logging()

def extract_protocol_17_fields(byte_array):
    date_time = byte_array[4:10]
    formatted_date_time = translate_date_time(date_time)

    latitude = bytes_to_latitude(byte_array[11:15])
    longitude = bytes_to_longitude(byte_array[15:19])

    total_seconds = int.from_bytes(byte_array[41:45], byteorder='big', signed=False)
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60

    mcc = int.from_bytes(byte_array[22:24], byteorder='big')
    mnc = byte_array[24]

    specific_fields = {
        "GPS Information": {   
            "Date Time": formatted_date_time,
            "Quantity of GPS Satellites": f"{byte_array[10]} - Total de Satélites GPS",
            "Latitude": latitude,
            "Longitude": longitude,
            "Speed": f"{int.from_bytes(byte_array[19:21], byteorder='big')} km/h",
            "Course Status": parse_course_status(byte_array[20:22])
        },
        "LBS Information": {            
            "MCC": f"{mcc} - {get_country_from_mcc(mcc)}",
            "MNC": f"{mnc} - {get_operator_from_mcc_mnc(mcc, mnc)}",
            "LAC": f"{int.from_bytes(byte_array[25:27], byteorder='big')} - {get_description_from_lac(int.from_bytes(byte_array[25:27], byteorder='big'))}",
            "Cell ID": f"{int.from_bytes(byte_array[27:30], byteorder='big')} - {get_description_from_cell_id(int.from_bytes(byte_array[27:30], byteorder='big'))}",
        },
        "Status Information": {
            "Device Status": "Active" if byte_array[30] & 0x01 else "Inactive",
            "Battery Voltage Level": f"{int.from_bytes(byte_array[31:32], byteorder='big')} - Nível da Bateria",
            "GSM Signal Strength": f"{byte_array[32]}%",
            "Battery Voltage": f"{int.from_bytes(byte_array[33:35], byteorder='big') / 100:.2f}V",
            "External Voltage": f"{int.from_bytes(byte_array[35:37], byteorder='big') / 100:.2f}V",
        },
        "Mileage": f"{int.from_bytes(byte_array[37:41], byteorder='big', signed=False)} m",
        "Hourmeter": f"{hours} h {minutes} min {seconds} s",
        "Information Serial Number": int.from_bytes(byte_array[45:47], byteorder='big', signed=False),
        "Error Check": int.from_bytes(byte_array[47:49], byteorder='big', signed=False),
        "End Bit": byte_array[49:51].hex().upper(),
    }

    return specific_fields









def translate_gps_sattelites(quantity):
    if quantity == 0:
        return "Sem Satélites"
    elif quantity == 1:
        return "1 Satélite"
    elif 2 <= quantity <= 5:
        return f"{quantity} Satélites"
    else:
        return f"{quantity} Satélites ou mais"


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

def translate_speed(speed_value):
    return f"{speed_value} km/h"


def parse_course_status(course_status_bytes):
    course_status = int.from_bytes(course_status_bytes, byteorder='big')

    reserved = (course_status >> 7) & 1
    din_status = (course_status >> 6) & 1
    gps_positioning_type = (course_status >> 5) & 1 
    gps_position = (course_status >> 4) & 1  
    longitude_direction = 'East' if (course_status >> 3) & 1 == 0 else 'West'
    latitude_direction = 'North' if (course_status >> 2) & 1 == 0 else 'South'

    course = course_status & 0x03

    return {
        "Reserved": reserved,
        "Din Status": din_status,
        "GPS Positioning Type": 'Tempo-Real' if gps_positioning_type == 0 else 'Diferenciado',
        "GPS Position": 'Não Posicionado' if gps_position == 0 else 'Posicionado',
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
}

# Mapeamento de MNC das operadoras
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
    "460": { # China
        "04": "Global Star",
        "09": "China Unicom",
        "20": "China Tietong"
    },
}


lac_mapping = {
    12345: "Área 1",
    23456: "Área 2",
    34567: "Área 3",
}

def get_description_from_lac(lac):
    return lac_mapping.get(lac, "Descrição Desconhecida")

def get_country_from_mcc(mcc):
    mcc_str = str(mcc)
    return mcc_country_mapping.get(mcc_str, "País Desconhecido")

def get_operator_from_mcc_mnc(mcc, mnc):
    mcc_str = str(mcc)
    mnc_str = f"{mnc:02X}"
    if mcc_str in mnc_mapping:
        return mnc_mapping[mcc_str].get(mnc_str, "Operadora Desconhecida")
    return "Operadora Desconhecida"

cell_id_mapping = {
    123456: "Célula 1",
    234567: "Célula 2",
    345678: "Célula 3",
}

def get_description_from_cell_id(cell_id):
    return cell_id_mapping.get(cell_id, "Descrição Desconhecida")

def translate_battery_voltage_level(byte_value):
    levels = {
        0: "Energia mais baixa e irá desligar",
        1: "Não possui energia suficiente para realizar chamada ou mensagem",
        2: "Baixa energia e alarme",
        3: "Baixa energia mas consegue funcionar normalmente",
        4: "Funcionando em ótima condição",
        5: "Funcionando em boa condição",
        6: "Funcionando em condição excelente",
    }
    return levels.get(byte_value, "Status desconhecido da bateria")

def parse_battery_voltage_level(byte_value):
    if byte_value == 0:
        return "Energia mais baixa e irá desligar"
    elif byte_value == 1:
        return "Não possui energia suficiente para realizar chamada ou mensagem"
    elif byte_value == 2:
        return "Baixa energia e alarme"
    elif byte_value == 3:
        return "Baixa energia mas consegue funcionar normalmente"
    elif 3 <= byte_value <= 6:
        return "Funcionando em ótima condição"
    else:
        return "Status desconhecido da bateria"

def parse_gsm_signal_strength(byte_value):
    if byte_value == 0:
        return "Sem sinal"
    elif byte_value == 100:
        return "Sinal está cheio"
    elif 0 < byte_value < 100:
        return f"Value: {byte_value}%"
    else:
        return "Sinal desconhecido GSM"

def parse_battery_voltage_level(byte_array):
    voltage_value = int.from_bytes(byte_array, byteorder='big') / 100.0
    return f"{voltage_value:.2f}V"

def parse_external_voltage(byte_array):
    external_voltage_value = int.from_bytes(byte_array, byteorder='big') / 100.0
    return f"{external_voltage_value:.2f}V"

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

def signal_handler(sig, frame):
    print("Interrompendo o servidor...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start_server(host='localhost', port=5050):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        logging.info(f"Servidor rodando em {host}:{port}...")
        
        while True:
            conn, addr = server_socket.accept()
            with conn:
                logging.info(f"Conexão aceita de {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    try:
                        packet_info = parse_hex_strings(data.hex())
                        for key, value in packet_info.items():
                            print(f"{key}: {value}") 
                    except Exception as e:
                        handle_error(e, addr)

if __name__ == "__main__":
    start_server()
