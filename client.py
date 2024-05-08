import socket
import os
import secrets
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

def main():
    host = input("Enter target host => ")
    port = int(input("Enter target port => "))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("Connected to server, handshaking...")

        keyfile = f'{host.replace(".", "")}_{port}.key'
        key = [secrets.token_hex(8), os.getlogin()]

        if os.path.exists(keyfile):
            with open(keyfile, 'r') as file:
                key = file.read().split(':')
        else:
            print("Generating new key...")
            id = input(f"Enter your unique identifier (empty defaults to '{os.getlogin()}') => ")
            if not id:
                id = os.getlogin()

            key[1] = id

            with open(keyfile, 'w') as file:
                file.write(f':'.join(key))

        print("Authenticating with key...")
        s.send(("AUTH" + f':'.join(key)).encode())
        
        auth_response = s.recv(1024).decode()
        print(auth_response)

        while True:

            print("\n1. List files on server\n2. Download file\n3. Quit")
            choice = input("Enter your choice: ")

            if choice == '1':
                 s.send(encrypt(key[0], 'LIST'.encode()))
                 files = decrypt(key[0], s.recv(1024))
                 print("Files on server:")
                 print(files)
            elif choice == '2':
                filename = input("Enter filename to download: ")

                s.send(encrypt(key[0], f'GET {filename}'.encode()))
                data = decrypt(key[0], s.recv(1024)).decode()
                if data == b'File not found':
                    print("File not found on server")
                else:
                    with open(filename, 'w') as f:
                        f.write(data)
                    print(f"{filename} downloaded successfully")
            elif choice == '3':
                break
            else:
                print("Invalid choice")

if __name__ == "__main__":
    main()