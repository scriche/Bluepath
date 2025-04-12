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
import bcrypt
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

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

# AES decryption key (replace with your actual key)
AES_KEY = b'Tz5SR0hrih4gVFCPILcyp+Sug9S9TS2+'

# Load users from JSON file and hash passwords
def load_users():
    global users
    try:
        with open('users.json', 'r') as f:
            raw_users = json.load(f)
            users = {username: bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode() for username, password in raw_users.items()}
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

# Load node positions
def load_node_positions():
    global nodepos
    nodepos = []  # Initialize as empty

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
        
        try:
            # Open the users.json file in real-time
            with open('users.json', 'r') as f:
                raw_users = json.load(f)
        except FileNotFoundError:
            return jsonify({'success': False, 'message': 'User database not found'})

        # Check if the username exists and verify the password in real-time
        if username in raw_users and bcrypt.checkpw(password.encode(), raw_users[username].encode()):
            session['username'] = username
            return jsonify({'success': True})
        
        # If authentication fails
        return jsonify({'success': False, 'message': 'Invalid username or password'})
    
    # Render the login page for GET requests
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
    for i in range(len(log_data[ip])):  # Fix the iteration
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
    layout_elements.append({
        'type': data['type'],
        'x': data['x'],
        'y': data['y'],
        'side': data['side']
    })
    save_layout()
    return 'Layout element saved', 200
@app.route('/save_layout_element', methods=['DELETE'])
def delete_layout_element():
    global layout_elements
    data = request.get_json()
    element = {
        'type': data['type'],
        'x': data['x'],
        'y': data['y'],
        'side': data['side']
    }
    if element in layout_elements:
        layout_elements.remove(element)
        save_layout()
        return 'Layout element deleted', 200
    return 'Layout element not found', 404

def trilaterate_least_squares(nodes, distances):
    """
    Perform trilateration using a least-squares approach.
    nodes: List of tuples [(x1, y1), (x2, y2), ...]
    distances: List of distances [r1, r2, ...]
    """
    A = []
    b = []
    for i in range(len(nodes)):
        x, y = nodes[i]
        A.append([2 * (x - nodes[0][0]), 2 * (y - nodes[0][1])])
        b.append(distances[0]**2 - distances[i]**2 - nodes[0][0]**2 - nodes[0][1]**2 + x**2 + y**2)
    A = np.array(A[1:])  # Exclude the first row (reference point)
    b = np.array(b[1:])  # Exclude the first element
    position = np.linalg.lstsq(A, b, rcond=None)[0]
    return position[0], position[1]

def calulate_position():
    address_distance_from_node = {}
    address_names = {}  # Dictionary to store names associated with addresses
    for ip, logs in log_data.items():
        for log in logs:
            address, rssi, name = log[2], log[3], log[1]
            if address not in address_distance_from_node:
                address_distance_from_node[address] = []
            address_distance_from_node[address].append((ip, float(rssi) * -0.2 - 10))
            address_names[address] = name  # Store the name associated with the address
    for address, distances in address_distance_from_node.items():
        if len(distances) >= 3 and len(nodepos) >= 3:
            # Match nodes by their IP addresses
            try:
                nodes = []
                dist = []
                for ip, rssi in distances:
                    node = next(node for node in nodepos if node[0] == ip)
                    nodes.append((node[1], node[2]))
                    dist.append(rssi * 25)  # Convert to grid coordinates
            except StopIteration:
                print(f"Error: One or more nodes are missing for address {address}.")
                continue

            try:
                x, y = trilaterate_least_squares(nodes, dist)
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
    return restricted_devices

@socketio.on('node_moved')
def handle_node_moved(data):
    nodepos.clear()
    for node in data['nodes']:
        nodepos.append((node['ip'], node['x'], node['y']))
    calulate_position()
    restricted_devices = find_devices_in_restricted_zones()
    try:
        socketio.emit('update_nodes', {'nodes': nodepos}, broadcast=True)
        socketio.emit('update_logs', {'log_data': log_data, 'address_coordinates': address_coordinates, 'restricted_devices': restricted_devices}, broadcast=True)
    except TypeError as e:
        print(f"Error emitting socket event: {e}")

# AES-256 decryption function
def decrypt_aes256(encrypted_data):
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, encrypted_data[:16])  # First 16 bytes are the IV
        decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
        print(f"Decrypted data: {decrypted_data.decode()}")
        return decrypted_data.decode()
    except Exception as e:
        print(f"Error decrypting data: {e}")
        return None

def udp_server(server_ip, server_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((server_ip, server_port))
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        data, addr = sock.recvfrom(2048)
        encrypted_log = data.decode().split('|')[0]
        #ip = addr[0]
        ip = data.decode().split('|')[1]
        #decrypted_log = decrypt_aes256(encrypted_log)
        decrypted_log = encrypted_log
        if decrypted_log:
            requests.post('http://127.0.0.1:8080/logs', json={'ip': ip, 'log': decrypted_log})

if __name__ == "__main__":
    load_node_positions()  # Load node positions on startup
    server_ip = '0.0.0.0'
    server_port = 5656
    threading.Thread(target=udp_server, args=(server_ip, server_port)).start()
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)