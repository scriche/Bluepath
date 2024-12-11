import socket
import threading
from flask import Flask, render_template, request, jsonify
from collections import defaultdict
import requests
import numpy as np
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
log_data = defaultdict(list)
address_coordinates = {}
nodepos = []

@app.route('/')
def index():
    return render_template('index.html', log_data=log_data, address_coordinates=address_coordinates)

@app.route('/update_nodespos', methods=['POST'])
def update_nodespos():
    data = request.get_json()
    nodepos.clear()
    for node in data:
        nodepos.append((node['ip'], node['x'], node['y']))
    return 'Node positions updated', 200

@app.route('/get_nodespos', methods=['GET'])
def get_nodespos():
    for ip in log_data:
        if log_data[ip] and ip not in [node[0] for node in nodepos]:
            nodepos.append((ip, 0, 0))
    return jsonify({'nodes': [{'ip': node[0], 'x': node[1], 'y': node[2]} for node in nodepos]}), 200

@app.route('/get_address_coordinates', methods=['GET'])
def get_address_coordinates():
    return jsonify({'address_coordinates': [{'address': address, 'x': x, 'y': y} for address, (x, y) in address_coordinates.items()]}), 200

@app.route('/logs', methods=['POST'])
def receive_log():
    data = request.get_json()
    ip = data['ip']
    log = data['log']
    
    if ip not in log_data:
        log_data[ip] = []

    log_data[ip] = log.split('\n')[:-1]
    for i in range(len(log_data[ip])):
        log_data[ip][i] = log_data[ip][i].split(',')
    calulate_position()
    
    return 'Log received', 200

def trilaterate(node_a, r1, node_b, r2, node_c, r3):
    # Calculate the coordinates of the address using trilateration
    # r1, r2, r3 are the distances from the address to the nodes
    # node_a, node_b, node_c are the coordinates of the nodes
    # Multiply r1, r2, r3 by 50 to convert to grid coordinates
    x0, y0 = node_a[1], node_a[2]
    x1, y1 = node_b[1], node_b[2]
    x2, y2 = node_c[1], node_c[2]
    r1, r2, r3 = r1 * 50, r2 * 50, r3 * 50

    # Convert (x0, y0), (x1, y1), and (x2, y2) into variables for solving
    A = 2 * (x1 - x0)
    B = 2 * (y1 - y0)
    C = r1**2 - r2**2 - x0**2 - y0**2 + x1**2 + y1**2
    D = 2 * (x2 - x0)
    E = 2 * (y2 - y0)
    F = r1**2 - r3**2 - x0**2 - y0**2 + x2**2 + y2**2

    # Solve for x and y
    denominator = A * E - B * D
    if denominator == 0:
        raise ValueError("The nodes are collinear; trilateration is not possible.")

    x = (C * E - B * F) / denominator
    y = (A * F - C * D) / denominator

    return x, y

def calulate_position():
    address_distance_from_node = {}
    for ip, logs in log_data.items():
        for log in logs:
            address, rssi = log[2], log[3]
            if address not in address_distance_from_node:
                address_distance_from_node[address] = []
            address_distance_from_node[address].append((float(rssi)*-0.2 - 10))
    for address, distances in address_distance_from_node.items():
        if len(distances) == 3:
            node_a = nodepos[0]
            node_b = nodepos[1]
            node_c = nodepos[2]
            r1, r2, r3 = distances
            address_coordinates[address] = trilaterate(node_a, r1, node_b, r2, node_c, r3)

def udp_server(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        data, addr = sock.recvfrom(2048)
        log = data.decode().split('|')[0]
        #ip = addr[0]
        ip = data.decode().split('|')[1]
        requests.post('http://127.0.0.1:8080/logs', json={'ip': ip, 'log': log})

if __name__ == "__main__":
    server_ip = '0.0.0.0'
    server_port = int(input("Enter the server port: "))
    threading.Thread(target=udp_server, args=(server_ip, server_port)).start()
    app.run(host='0.0.0.0', port=8080)