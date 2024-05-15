import socket
import os
from pyDes import des, PAD_PKCS5
import base64
from inputimeout import inputimeout

authed = False

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
    
   
def receive_file(conn, filename, keyuser):
    print(f"Receiving '{filename}' from: {keyuser[1]}")
    
    data = b''

    if os.path.exists(filename):
        os.remove(filename)
    
    receive = True
    while receive:
        chunk = conn.recv(1024)

        if chunk == b'EOF':
            receive = False
            break
        elif chunk.endswith(b'EOF'):
            chunk = chunk[:-3] # Remove EOF
            receive = False

        data = decrypt(keyuser[0], chunk)

        try:
            if data.decode() == 'FILE_NOT_FOUND':
                print("ERROR: FILE_NOT_FOUND! (In the client)")
                return
        except:
            pass

        with open(filename, 'ab') as f:
            f.write(data)

def handle_client(conn, addr):
    global authed
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
                            conn.send('Failed to auth: WRONG_KEY_OR_USERNAME'.encode())
                            conn.close()
                            break
                else:
                    try: 
                        if inputimeout(prompt=f"To add & auth new user {keyuser[1]} enter 'yes' within 10s: ", timeout=10) == 'yes':
                             with open(keyfile, 'w') as file:
                                print(f"New key file added: {keyfile} from {keyuser[1]} at {addr}")
                                file.write(keyuser[0])
                        else:
                            raise Exception()
                    except Exception: 
                        conn.send('Failed to auth: NOT_REGISTERED'.encode())
                        conn.close()
                        print(f'{keyuser[1]} at {addr} was denied authentication')
                        return

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
            elif request.startswith('POST'):
                filename = request.split()[1]
                receive_file(conn, filename, keyuser)
                print("Received!")   
                
    conn.close()

def main():
    global authed
    host = '127.0.0.1'
    port = int(input('Enter listen port => '))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(5)
        print(f"Server listening on {host}:{port}")

        while True:
            print('\nWaiting for connection...')
            authed = False
            conn, addr = s.accept()
            print(f"Incoming connection from {addr}, waiting for handshake...")
            handle_client(conn, addr)

if __name__ == "__main__":
    main()