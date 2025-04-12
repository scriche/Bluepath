import time
import socket
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
import base64

# AES encryption key (must match the server's key)
AES_KEY = b'Tz5SR0hrih4gVFCPILcyp+Sug9S9TS2+bbgqU/QXOVQ='

# AES-256 encryption function
def encrypt_aes256(data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC)
        iv = cipher.iv  # Initialization vector
        encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
        return base64.b64encode(iv + encrypted_data).decode()  # Combine IV and encrypted data
    except Exception as e:
        print(f"Error encrypting data: {e}")
        return None

def send_log_file(server_ip, server_port, log_file_path):
    with open(log_file_path, 'r') as file:
        log_data = file.read()
    
    encrypted_log = encrypt_aes256(log_data)  # Encrypt the log data
    if not encrypted_log:
        print("Failed to encrypt log data. Skipping...")
        return

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(encrypted_log.encode(), (server_ip, server_port))  # Send encrypted data
    except socket.error as e:
        print(f"Error sending log file: {e}")
    finally:
        if sock:
            sock.close()

def main():
    server_ip = input("Enter the server IP address: ")
    server_port = 5656
    log_file_path = "./bluepath.log"
    print(f"Sending log file to {server_ip}:{server_port}...")

    while True:
        send_log_file(server_ip, server_port, log_file_path)
        time.sleep(3)

if __name__ == "__main__":
    main()