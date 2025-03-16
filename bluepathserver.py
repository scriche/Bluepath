import socket
import threading
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_socketio import SocketIO, emit
from collections import defaultdict
import requests
import numpy as np
from flask_cors import CORS
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'your_secret_key'
CORS(app)
socketio = SocketIO(app)
log_data = defaultdict(list)
address_coordinates = {}
nodepos = []
authorized_macs = set()
restrictedzones = []
users = {}
device_history = defaultdict(dict)  # Change to defaultdict(dict)
last_update_time = defaultdict(lambda: datetime.min)  # Track the last update time for each address
layout_elements = []

# Load users from JSON file
def load_users():
    global users
    try:
        with open('users.json', 'r') as f:
            users = json.load(f)
    except FileNotFoundError:
        pass

# Load authorized MAC addresses and restricted zones from JSON files
def load_persistent_data():
    global authorized_macs, restrictedzones
    try:
        with open('authorized.json', 'r') as f:
            authorized_macs = set(json.load(f))
    except FileNotFoundError:
        pass
    try:
        with open('restricted.json', 'r') as f:
            restrictedzones = json.load(f)
    except FileNotFoundError:
        pass

# Load device history from JSON file
def load_device_history():
    global device_history
    try:
        with open('device_history.json', 'r') as f:
            device_history.update(json.load(f))
    except FileNotFoundError:
        pass

# Load node positions from JSON file
def load_node_positions():
    global nodepos
    try:
        with open('node_positions.json', 'r') as f:
            nodepos = json.load(f)
    except FileNotFoundError:
        pass

# Load layout elements from JSON file
def load_layout():
    global layout_elements
    try:
        with open('layout.json', 'r') as f:
            layout_elements = json.load(f)
    except FileNotFoundError:
        pass

# Save authorized MAC addresses to JSON file
def save_authorized_macs():
    with open('authorized.json', 'w') as f:
        json.dump(list(authorized_macs), f)

# Save restricted zones to JSON file
def save_restrictedzones():
    with open('restricted.json', 'w') as f:
        json.dump(restrictedzones, f)

# Save device history to JSON file
def save_device_history():
    with open('device_history.json', 'w') as f:
        json.dump(device_history, f, default=dict, indent=4)  # Add indent for better readability

# Save node positions to JSON file
def save_node_positions():
    with open('node_positions.json', 'w') as f:
        json.dump(nodepos, f)

# Save layout elements to JSON file
def save_layout():
    with open('layout.json', 'w') as f:
        json.dump(layout_elements, f)

load_users()
load_persistent_data()
load_device_history()
load_node_positions()
load_layout()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        username = data['username']
        password = data['password']
        if username in users and users[username] == password:
            session['username'] = username
            return jsonify({'success': True})
        return jsonify({'success': False})
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', log_data=log_data, address_coordinates=address_coordinates, authorized_macs=authorized_macs)

@app.route('/device_history')
def get_device_history_page():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('device_history.html', address_coordinates=address_coordinates, authorized_macs=authorized_macs)

@app.route('/device_history/<address>', methods=['GET'])
def get_device_history(address):
    if 'username' not in session:
        return redirect(url_for('login'))
    history = device_history.get(address, {})
    # Convert the history dictionary to a list of entries
    history_list = []
    for date, entries in history.items():
        for entry in entries:
            history_list.append({'date': date, 'time': entry['time'], 'x': entry['x'], 'y': entry['y']})
    return jsonify({'history': history_list})

@app.route('/device_history.json')
def serve_device_history():
    try:
        with open('device_history.json', 'r') as f:
            return jsonify(json.load(f))
    except FileNotFoundError:
        return jsonify({}), 404

@app.route('/update_nodespos', methods=['POST'])
def update_nodespos():
    data = request.get_json()
    nodepos.clear()
    for node in data:
        nodepos.append((node['ip'], node['x'], node['y']))
    save_node_positions()
    socketio.emit('update_nodes', {'nodes': nodepos}, broadcast=True)
    return 'Node positions updated', 200

@app.route('/get_nodespos', methods=['GET'])
def get_nodespos():
    for ip in log_data:
        if log_data[ip] and ip not in [node[0] for node in nodepos]:
            nodepos.append((ip, 0, 0))
    return jsonify({'nodes': [{'ip': node[0], 'x': node[1], 'y': node[2]} for node in nodepos]}), 200

@app.route('/get_address_coordinates', methods=['GET'])
def get_address_coordinates():
    return jsonify({'address_coordinates': [{'address': address, 'x': x, 'y': y, 'name': name} for address, (x, y, name) in address_coordinates.items()]}), 200

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
    restricted_devices = find_devices_in_restricted_zones()
    
    socketio.emit('update_logs', {'log_data': log_data, 'address_coordinates': address_coordinates, 'restricted_devices': restricted_devices})
    return 'Log received', 200

@app.route('/authorized_macs', methods=['POST'])
def add_authorized_mac():
    data = request.get_json()
    mac = data['mac']
    authorized_macs.add(mac)
    save_authorized_macs()
    return 'Authorized MAC address added', 200

@app.route('/authorized_macs', methods=['GET'])
def get_authorized_macs():
    return jsonify({'authorized_macs': list(authorized_macs)}), 200

@app.route('/authorized_macs', methods=['DELETE'])
def delete_authorized_mac():
    data = request.get_json()
    mac = data['mac']
    if mac in authorized_macs:
        authorized_macs.remove(mac)
        save_authorized_macs()
        return 'Authorized MAC address deleted', 200
    return 'MAC address not found', 404

@app.route('/restrictedzones', methods=['POST'])
def add_restrictedzone():
    data = request.get_json()
    restrictedzone = data['restrictedzone']
    restrictedzones.append(restrictedzone)
    save_restrictedzones()
    return 'Restricted zone added', 200

@app.route('/restrictedzones/toggle', methods=['POST'])
def toggle_restrictedzone():
    data = request.get_json()
    x = data['x']
    y = data['y']
    restrictedzone = {'x': x, 'y': y}
    if restrictedzone in restrictedzones:
        restrictedzones.remove(restrictedzone)
        message = 'Restricted zone removed'
    else:
        restrictedzones.append(restrictedzone)
        message = 'Restricted zone added'
    save_restrictedzones()
    return message, 200

@app.route('/restrictedzones', methods=['GET'])
def get_restrictedzones():
    return jsonify({'restrictedzones': restrictedzones, 'restricted_devices': find_devices_in_restricted_zones()}), 200

@app.route('/restrictedzones', methods=['DELETE'])
def delete_restrictedzone():
    data = request.get_json()
    restrictedzone = data['restrictedzone']
    if restrictedzone in restrictedzones:
        restrictedzones.remove(restrictedzone)
        save_restrictedzones()
        return 'Restricted zone deleted', 200
    return 'Restricted zone not found', 404

@app.route('/refresh_nodespos', methods=['GET'])
def refresh_nodespos():
    try:
        socketio.emit('update_nodes', {'nodes': nodepos}, broadcast=True)
    except TypeError as e:
        print(f"Error emitting socket event: {e}")
    return 'Node positions refreshed', 200

@app.route('/get_layout', methods=['GET'])
def get_layout():
    return jsonify({'layout': layout_elements}), 200

@app.route('/save_layout', methods=['POST'])
def save_layout_route():
    global layout_elements
    data = request.get_json()
    layout_elements = data['layout']
    save_layout()
    return 'Layout saved', 200

@app.route('/save_layout_element', methods=['POST'])
def save_layout_element():
    global layout_elements
    data = request.get_json()
    layout_elements.append(data)
    save_layout()
    return 'Layout element saved', 200

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
    address_names = {}  # Dictionary to store names associated with addresses
    for ip, logs in log_data.items():
        for log in logs:
            address, rssi, name = log[2], log[3], log[1]
            if address not in address_distance_from_node:
                address_distance_from_node[address] = []
            address_distance_from_node[address].append((float(rssi)*-0.2 - 10))
            address_names[address] = name  # Store the name associated with the address
    for address, distances in address_distance_from_node.items():
        if len(distances) == 3 and len(nodepos) >= 3:
            node_a = nodepos[0]
            node_b = nodepos[1]
            node_c = nodepos[2]
            r1, r2, r3 = distances
            try:
                x, y = trilaterate(node_a, r1, node_b, r2, node_c, r3)
                x, y = round(x), round(y)  # Round coordinates to whole numbers
                name = address_names.get(address, address)  # Get the name or fallback to address
                address_coordinates[address] = (x, y, name)
                # Store the location history under today's date with a different timestamp every 30 seconds
                date_str = str(datetime.now().date())
                time_str = str(datetime.now().time())
                if date_str not in device_history[address]:
                    device_history[address][date_str] = []
                # Check if the last entry was added more than 30 seconds ago
                if (datetime.now() - last_update_time[address]) > timedelta(seconds=30):
                    device_history[address][date_str].append({'time': time_str, 'x': x, 'y': y})
                    last_update_time[address] = datetime.now()
                    save_device_history()
            except ValueError as e:
                print(f"Error calculating position for address {address}: {e}")

def find_devices_in_restricted_zones():
    restricted_devices = []
    for address, (x, y, name) in address_coordinates.items():
        if address not in authorized_macs:
            for zone in restrictedzones:
                if zone['x'] < x + 20 and x < zone['x'] + 25 and zone['y'] < y + 20 and y < zone['y'] + 25:
                    restricted_devices.append(address)
                    break
    print(restricted_devices)
    return restricted_devices

@socketio.on('node_moved')
def handle_node_moved(data):
    nodepos.clear()
    for node in data['nodes']:
        nodepos.append((node['ip'], node['x'], node['y']))
    save_node_positions()
    calulate_position()
    restricted_devices = find_devices_in_restricted_zones()
    try:
        socketio.emit('update_nodes', {'nodes': nodepos}, broadcast=True)
        socketio.emit('update_logs', {'log_data': log_data, 'address_coordinates': address_coordinates, 'restricted_devices': restricted_devices}, broadcast=True)
    except TypeError as e:
        print(f"Error emitting socket event: {e}")

def udp_server(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        data, addr = sock.recvfrom(2048)
        log = data.decode().split('|')[0]
        ip = data.decode().split('|')[1]
        requests.post('http://127.0.0.1:8080/logs', json={'ip': ip, 'log': log})

if __name__ == "__main__":
    server_ip = '0.0.0.0'
    # server_port = int(input("Enter the logging port: "))
    server_port = 5656
    threading.Thread(target=udp_server, args=(server_ip, server_port)).start()
    socketio.run(app, host='0.0.0.0', port=8080)