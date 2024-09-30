import socket
import logging
import threading

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

setup_logging()

def parse_hex_packet(packet):
    start_bit = packet[:2]
    length = packet[2:3]
    protocol_number = packet[3:4]
    device_id = packet[4:12]
    info_serial_number = packet[12:14]
    error_check = packet[14:16]
    end_bit = packet[-2:]

    logging.info(f"Start Bit: {start_bit.hex()}, Length: {length.hex()}, Protocol Number: {protocol_number.hex()}, "
                 f"Device ID: {device_id.hex()}, Information Serial Number: {info_serial_number.hex()}, "
                 f"Error Check: {error_check.hex()}, End Bit: {end_bit.hex()}")

    return {
        "start_bit": start_bit.hex(),
        "length": length.hex(),
        "protocol_number": protocol_number.hex(),
        "device_id": device_id.hex(),
        "info_serial_number": info_serial_number.hex(),
        "error_check": error_check.hex(),
        "end_bit": end_bit.hex()
    }

def handle_client_connection(conn, addr):
    logging.info(f"Conexão estabelecida com {addr}")

    while True:
        try:
            data = conn.recv(1024)
            if not data:
                logging.info("Conexão fechada pelo cliente.")
                break
            
            logging.info(f"Dados recebidos: {data.hex()}")
            parsed_packet = parse_hex_packet(data)
            logging.info(f"Pacote decodificado: {parsed_packet}")


        except Exception as e:
            logging.error(f"Erro: {e}")
            break
    conn.close()
    logging.info(f"Conexão com {addr} fechada.")

def start_server(host='0.0.0.0', port=5050):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        logging.info(f"Servidor escutando em {host}:{port}")
        
        while True:
            conn, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client_connection, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    start_server()
