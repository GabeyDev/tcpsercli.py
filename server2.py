import socket

def identificar_pares_hexadecimal(pacote_hex):
    start_bit = '7878'
    end_bit = '0d0a'
    
    pos_start = pacote_hex.find(start_bit)
    print(f"Posição do start bit ('{start_bit}'): {pos_start}")
    
    if pos_start == -1:
        return {'start_bit': '7878', 'pos_start_bit': 0, 'end_bit': '0D0A', 'pos_end_bit': 32}
    
    pos_end = pacote_hex.find(end_bit)
    print(f"Posição do end bit ('{end_bit}'): {pos_end}")
    
    if pos_end == -1:
        return {'start_bit': pos_start, 'pos_start_bit': len(start_bit) // 2, 'end_bit': '0D0A', 'pos_end_bit': 32}
    
   
    pos_start_bit = len(start_bit) // 2
    pos_end_bit = len(end_bit) // 2
    
    return {
        'start_bit': pos_start,
        'pos_start_bit': pos_start_bit,
        'end_bit': pos_end,
        'pos_end_bit': pos_start_bit
    }

def main():
    host = '127.0.0.1'
    port = 5050

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        print(f"Servidor TCP ouvindo o host {host}: e o port {port}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Conectado por {addr}")
                data = conn.recv(1024)
                
                if data:
                    pacote_hex = data.hex().upper()
                    print(f"Pacote recebido: {pacote_hex}")
                    
                    resultado = identificar_pares_hexadecimal(pacote_hex)
                    print(f"Resultado da identificação: {resultado}")
                    
                    resposta = str(resultado).encode('utf-8')
                    conn.sendall(resposta)

if __name__ == "__main__":
    main()
