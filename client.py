import os, time, socket, secrets, base64
from pyDes import des, PAD_PKCS5
import base64
from inputimeout import inputimeout

def encrypt(key, message):
    k = des(bytes.fromhex(key), padmode=PAD_PKCS5)
    encrypted_message = k.encrypt(message)
    return base64.b64encode(encrypted_message)

def decrypt(key, encrypted_message):
    k = des(bytes.fromhex(key), padmode=PAD_PKCS5)
    decrypted_message = k.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message

def receive_file_list(conn, keyuser):
    files = []
    receive = True
    while receive:
        file = conn.recv(1024)

        if file == b'EOF':
            receive = False
            break
        elif file.endswith(b'EOF'):
            file = file[:-3]
            receive = False

        if file:
            files.append(decrypt(keyuser[0], file).decode())

    return files

def download_file(conn, filename, keyuser):
    data = b''
    
    if not os.path.exists('downloads'):
        os.makedirs('downloads')

    if os.path.exists(os.path.join('downloads', filename)):
        os.remove(os.path.join('downloads', filename))
    
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
                print("ERROR: FILE_NOT_FOUND! (In the server)")
                return
        except:
            pass

        with open(os.path.join('downloads', filename), 'ab') as f:
            f.write(data)

    print(f"{filename} downloaded successfully")
    
def send_file(conn, filename, keyuser):
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
        print(f'Tried to send {filename} with error: FILE_NOT_FOUND')
    
    conn.send(b'EOF')
    print(f'{filename} sent to server!')

def main():
    host = input("Enter target host => ")
    port = int(input("Enter target port => "))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("Connected to server, handshaking...")

        keyfile = f'{host.replace(".", "")}_{port}.key'
        keyuser = [secrets.token_hex(8), os.getlogin()]

        if os.path.exists(keyfile):
            with open(keyfile, 'r') as file:
                keyuser = file.read().split(':')
        else:
            print("Generating new key...")

            id = os.getlogin()
            try: 
                id = inputimeout(prompt=f"Enter your unique identifier (defaults to '{os.getlogin()}' in 10s) => ", timeout=10)
            except Exception: 
                id = os.getlogin()

            if not id:
                id = os.getlogin()

            keyuser[1] = id

        print(f"Authenticating with '{keyfile}'")
        s.send(("AUTH" + f':'.join(keyuser)).encode())
        
        auth_response = s.recv(1024).decode()
        try:
            decryptedresp = decrypt(keyuser[0], auth_response).decode()
            print(decryptedresp)
            if decryptedresp != "Authenticated":
                raise ConnectionError()
            
            if not os.path.exists(keyfile):
                with open(keyfile, 'w') as file:
                    file.write(f':'.join(keyuser))
                    print('Key file created!')
        except:
            print("Failed to authenticate!")
            s.close()
            return

        while True:

            print("\n1. List files on server\n2. Download file\n3. Send file\n4. Quit")
            choice = input("Enter your choice: ")

            if choice == '1':
                 print('Requesting file list:')

                 s.send(encrypt(keyuser[0], 'LIST'.encode()))
                 files = receive_file_list(s, keyuser)

                 print("Filelist received:")
                 print(files)
            elif choice == '2':
                filename = input("Enter filename to download: ")

                print(f'Requesting file: {filename}')
                s.send(encrypt(keyuser[0], f'GET {filename}'.encode()))
                download_file(s, filename, keyuser)
            elif choice == '3':
                files = os.listdir('.')
                print(files)
                
                filename = input("Enter filename to send: ")

                if not os.path.exists(filename):
                    print("Invalid file!")
                    time.sleep(2)
                    continue

                print(f"Sending file '{filename}' to server...")
                s.send(encrypt(keyuser[0], f'POST {filename}'.encode()))
                send_file(s, filename, keyuser)
            elif choice == '4':
                break
            else:
                print("Invalid choice")

            time.sleep(1)

if __name__ == "__main__":
    main()