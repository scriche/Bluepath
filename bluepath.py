import asyncio
import pydbus
from gi.repository import GLib
from pathlib import Path
from datetime import datetime
import threading

log_file = Path('./bluepath.log')

# Clear the log file at the start of the program
log_file.open('w').close()

def write_to_log(address, rssi, name):
    """Write device, rssi values, and name to a log file"""
    now = datetime.now()
    current_time = now.strftime('%H:%M:%S')
    with log_file.open('a') as dev_log:
        dev_log.write(f'{current_time},{name},{address},{rssi}\n')

def remove_from_log(address):
    """Remove device entry from the log file"""
    if log_file.exists():
        with log_file.open('r') as dev_log:
            lines = dev_log.readlines()
        with log_file.open('w') as dev_log:
            for line in lines:
                if address not in line:
                    dev_log.write(line)

def update_devices(devices):
    """Scan devices dictionary for devices and update the log file with the 
    new RSSI values and remove devices that are out of range"""
    log_file.open('w').close()
    for addr, device in devices.items():
        device_properties = device.GetAll('org.bluez.Device1')
        rssi = device_properties.get('RSSI')
        name = device_properties.get('Name', 'Unknown')
        if rssi:
            write_to_log(addr, rssi, name)
        else:
            del devices[addr]
            print(f'Device out of range {name} ({addr})')
bus = pydbus.SystemBus()
mainloop = GLib.MainLoop()
devices = {}

def discovery(path_obj):
    device = bus.get('org.bluez', path_obj)
    try:
        device_properties = device.GetAll('org.bluez.Device1')
    except Exception as e:
        print(f'Error getting device properties')
        return
    rssi = device_properties.get('RSSI')
    name = device_properties.get('Name', 'Unknown')
    if rssi:
        print(f'Device added to monitor {name} ({device.Address}) @ {rssi} dBm')
        # Add device to devices dictionary
        devices[device.Address] = device

def new_iface(path, iface_props):
    device_addr = iface_props.get('org.bluez.Device1', {}).get('Address')
    if device_addr:
        discovery(path)

def start_updater():
    threading.Timer(3.0, start_updater).start()
    update_devices(devices)
    
# Bluez object manager
mngr = bus.get('org.bluez', '/')
mngr.onInterfacesAdded = new_iface

adapter = bus.get('org.bluez', '/org/bluez/hci0')
adapter.DuplicateData = False

adapter.StartDiscovery()
print('Finding devices...')

try:
    start_updater()
    mainloop.run()
except KeyboardInterrupt:
    # Stop discovery and exit the program
    adapter.StopDiscovery()
    mainloop.quit()
    print('Exiting...')