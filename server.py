import socket
import os
from pyDes import des, PAD_PKCS5
import base64

def pad_data(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len] * pad_len)

def encrypt(key, message):
    k = des(bytes.fromhex(key), PAD_PKCS5)
    # Pad the message to make its length a multiple of 8
    padded_message = pad_data(message)
    encrypted_message = k.encrypt(padded_message)
    return base64.b64encode(encrypted_message)

def decrypt(key, encrypted_message):
    k = des(bytes.fromhex(key), PAD_PKCS5)
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = k.decrypt(encrypted_message)
    return decrypted_message


def list_files():
    files = os.listdir('.')
    return '\n'.join(files)

def send_file(conn, filename):
    try:
        with open(filename, 'rb') as f:
            data = f.read()
            conn.send(data)
    except FileNotFoundError:
        conn.send(b'File not found')

def handle_client(conn):
    authed = False
    while True:
        request = conn.recv(1024)
    
        if not request:
            break

        if not authed:
            request = request.decode()
            if request.startswith("AUTH"):
                data = request.replace("AUTH", "") 
                key = data.split(':') 
                
                print(f"User identifier is: {key[1]} (Key: {key[0]})")
                keyfile = f'{key[1]}.key'
                if os.path.exists(keyfile):
                    with open(keyfile, 'r') as file:
                        read = file.read()

                        if read != key[0]:
                            print("Invalid key, disconnecting them!")
                            conn.send('Failed to auth: WRONG KEY OR CHANGE USERNAME'.encode())
                            conn.close()
                            break
                else:
                    with open(keyfile, 'w') as file:
                        print(f"New key file added: {keyfile}")
                        file.write(key[0])
                
                authed = True
                
                conn.send(encrypt(key[0], 'Authenticated'.encode()))
        elif authed:
            request = decrypt(key[0], request).decode()

            if request == 'LIST':
                files = list_files()
                conn.send(encrypt(key[0], files.encode()))
            elif request.startswith('GET'):
                filename = request.split()[1]
                send_file(conn, filename)
    conn.close()

def main():
    host = '127.0.0.1'
    port = int(input('Enter listen port => '))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(5)
        print(f"Server listening on {host}:{port}")

        while True:
            conn, addr = s.accept()
            print(f"Incoming connection from {addr}, waiting for handshake...")
            handle_client(conn)

if __name__ == "__main__":
    main()
