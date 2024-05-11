import socket
import os
from pyDes import des, PAD_PKCS5, PAD_NORMAL
import base64
import random

def encrypt(key, message):
    k = des(bytes.fromhex(key), padmode=PAD_PKCS5)
    encrypted_message = k.encrypt(message)
    return base64.b64encode(encrypted_message)

def decrypt(key, encrypted_message):
    k = des(bytes.fromhex(key), padmode=PAD_PKCS5)
    decrypted_message = k.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message

def send_file_list(conn, keyuser):
    files = os.listdir('.')

    for file in files:
        conn.send(encrypt(keyuser[0], file.encode()))

    conn.send(b'EOF')

def send_file(conn, filename, keyuser):
    print(f"Sending '{filename}' to: {keyuser[1]}")
    try:
        with open(filename, 'rb') as f:
            while True:
                data = f.read(512)
                if not data:
                    break
                encrypted_data = encrypt(keyuser[0], data)
                conn.send(encrypted_data)
    except FileNotFoundError:
        conn.send(encrypt(keyuser[0], 'FILE_NOT_FOUND'.encode()))
        print(f'{keyuser[1]} tried to receive {filename} with error: FILE_NOT_FOUND')
    
    conn.send(b'EOF')

def handle_client(conn, addr):
    authed = False
    while True:
        request = conn.recv(1024)
    
        if not request:
            break

        if not authed:
            request = request.decode()
            if request.startswith("AUTH"):
                data = request.replace("AUTH", "") 
                keyuser = data.split(':') 
                
                print(f"User identifier is: {keyuser[1]} (Key: {keyuser[0]}) for {addr}")
                keyfile = f'{keyuser[1]}.key'
                if os.path.exists(keyfile):
                    with open(keyfile, 'r') as file:
                        read = file.read()

                        if read != keyuser[0]:
                            print(f"Invalid key for {keyuser[1]}, disconnecting {addr}!")
                            conn.send('Failed to auth: WRONG KEY OR CHANGE USERNAME'.encode())
                            conn.close()
                            break
                else:
                    with open(keyfile, 'w') as file:
                        print(f"New key file added: {keyfile} from {keyuser[1]} at {addr}")
                        file.write(keyuser[0])
                
                authed = True
                
                conn.send(encrypt(keyuser[0], 'Authenticated'.encode()))
        elif authed:
            request = decrypt(keyuser[0], request).decode()

            if request == 'LIST':
                print(f"Sending file list to: {keyuser[1]} at {addr}")
                send_file_list(conn, keyuser)
                print("Sent!")
            elif request.startswith('GET'):
                filename = request.split()[1]
                send_file(conn, filename, keyuser)
                print("Sent!")
                
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
            handle_client(conn, addr)

if __name__ == "__main__":
    main()