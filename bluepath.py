from datetime import datetime
from pathlib import Path
import pydbus
from gi.repository import GLib

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

bus = pydbus.SystemBus()
mainloop = GLib.MainLoop()

class DeviceMonitor:
    """Class to represent remote bluetooth devices discovered"""
    devices = {}

    def __init__(self, path_obj):
        self.device = bus.get('org.bluez', path_obj)
        self.device.onPropertiesChanged = self.prop_changed
        device_properties = self.device.GetAll('org.bluez.Device1')
        rssi = device_properties.get('RSSI')
        name = device_properties.get('Name', 'Unknown')
        if rssi:
            print(f'Device added to monitor {name} ({self.device.Address}) @ {rssi} dBm')
            DeviceMonitor.devices[self.device.Address] = self.device
            write_to_log(self.device.Address, rssi, name)
        else:
            print(f'Device added to monitor {name} ({self.device.Address})')
            write_to_log(self.device.Address, 'N/A', name)

    def prop_changed(self, iface, props_changed, props_removed):
        """method to be called when a property value on a device changes"""
        rssi = props_changed.get('RSSI', None)
        try:
            name = self.device.Get('org.bluez.Device1', 'Name')
        except GLib.GError:
            name = 'Unknown'
        if rssi is not None:
            print(f'\tDevice Seen: {name} ({self.device.Address}) @ {rssi} dBm')
            DeviceMonitor.devices[self.device.Address] = self.device
            write_to_log(self.device.Address, rssi, name)
        else:
            if self.device.Address in DeviceMonitor.devices:
                del DeviceMonitor.devices[self.device.Address]
                print(f'\tDevice {name} ({self.device.Address}) is out of range')
                remove_from_log(self.device.Address)

def end_discovery():
    """method called at the end of discovery scan"""
    mainloop.quit()
    adapter.StopDiscovery()

def new_iface(path, iface_props):
    """If a new dbus interfaces is a device, add it to be  monitored"""
    device_addr = iface_props.get('org.bluez.Device1', {}).get('Address')
    if device_addr:
        DeviceMonitor(path)

# BlueZ object manager
mngr = bus.get('org.bluez', '/')
mngr.onInterfacesAdded = new_iface

# Connect to the DBus api for the Bluetooth adapter
adapter = bus.get('org.bluez', '/org/bluez/hci0')
adapter.DuplicateData = False

# Run discovery indefinitely
adapter.StartDiscovery()
print('Finding nearby devices...')
try:
    mainloop.run()
except KeyboardInterrupt:
    adapter.StopDiscovery()

# Start the main loop to run indefinitely
mainloop.run()