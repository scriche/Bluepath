import asyncio
import pydbus
from gi.repository import GLib
from pathlib import Path
from datetime import datetime
import threading

log_file = Path('./bluepath.log')

# Clear the log file at the start of the program
log_file.open('w').close()

def write_to_log(devices):
    """Write all devices, rssi values, and names to a log file"""
    now = datetime.now()
    current_time = now.strftime('%H:%M:%S')
    devices_to_remove = []
    with log_file.open('w') as dev_log:
        for addr, device in list(devices.items()):
            try:
                device_properties = device.GetAll('org.bluez.Device1')
                rssi = device_properties.get('RSSI')
                name = device_properties.get('Name', 'Unknown')
                dev_log.write(f'{current_time},{name},{addr},{rssi}\n')
            except Exception as e:
                if 'org.freedesktop.DBus.Error.UnknownObject' in str(e):
                    devices_to_remove.append(addr)
                    print(f'Device out of range {addr}')
                else:
                    print(f'Error writing to log for device {addr}: {e}')
    for addr in devices_to_remove:
        del devices[addr]

def update_devices(devices):
    """Update the dictionary with the new RSSI values and remove devices that are out of range"""
    to_remove = []
    for addr, device in list(devices.items()):
        try:
            device_properties = device.GetAll('org.bluez.Device1')
            rssi = device_properties.get('RSSI')
            if rssi is None:
                to_remove.append(addr)
                print(f'Device out of range {device_properties.get("Name", "Unknown")} ({addr})')
        except Exception as e:
            if 'org.freedesktop.DBus.Error.UnknownObject' in str(e):
                to_remove.append(addr)
                print(f'Device out of range {addr}')
            else:
                print(f'Error updating device {addr}: {e}')
    for addr in to_remove:
        del devices[addr]

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
        if device.Address not in devices:
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
    write_to_log(devices)
    
# Bluez object manager
try:
    mngr = bus.get('org.bluez', '/')
    mngr.onInterfacesAdded = new_iface

    adapter = bus.get('org.bluez', '/org/bluez/hci0')
    adapter.DuplicateData = False

    adapter.StartDiscovery()
    print('Finding devices...')

    start_updater()
except Exception as e:
    print(f'Error initializing Bluez: {e}')

try:
    mainloop.run()
except KeyboardInterrupt:
    # Stop discovery and exit the program
    adapter.StopDiscovery()
    mainloop.quit()
    # Clear the log file
    log_file.open('w').close()
    print('Exiting...')