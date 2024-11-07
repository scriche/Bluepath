import socket
import threading
from flask import Flask, render_template, request
from collections import defaultdict

app = Flask(__name__)
log_data = defaultdict(list)

@app.route('/')
def index():
    return render_template('index.html', log_data=log_data)

@app.route('/logs', methods=['POST'])
def receive_log():
    data = request.get_json()
    ip = data['ip']
    log = data['log']
    log_data[ip].append(log)
    return 'Log received', 200

def udp_server(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        data, addr = sock.recvfrom(1024)
        log = data.decode()
        ip = addr[0]
        print(f"Received log from {ip}: {log}")
        requests.post('http://127.0.0.1:5000/logs', json={'ip': ip, 'log': log})

if __name__ == "__main__":
    server_ip = '0.0.0.0'
    server_port = int(input("Enter the server port: "))

    threading.Thread(target=udp_server, args=(server_ip, server_port)).start()
    app.run(debug=True)