import time
import socket

def send_log_file(server_ip, server_port, log_file_path):
    with open(log_file_path, 'r') as file:
        log_data = file.read()
    
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(log_data.encode(), (server_ip, server_port))
    except socket.error as e:
        print(f"Error sending log file: {e}")
    finally:
        if sock:
            sock.close()

def main():
    server_ip = input("Enter the server IP address: ")
    server_port = int(input("Enter the server port: "))
    log_file_path = "./bluepath.log"
    print(f"Sending log file to {server_ip}:{server_port}...")

    while True:
        send_log_file(server_ip, server_port, log_file_path)
        time.sleep(3)

if __name__ == "__main__":
    main()