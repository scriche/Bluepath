# Bluepath
This project aims to be a Bluetooth security and tracker system. Using the
bluepath will be able to scan for nearby bluetooth signal regardless if they are in
discoverable mode or not with one of the devices you can detect how many device
are in an area and tag each devices MAC address to a specific person or device
name allowing you to see if unauthorize devices/people are in a location. Utilizing
multiple of these devices will allow you to additionally locate the device
triangulating the signal strength and if they are in range of a Bluepath device. All
of this data will be presented in a simple dashboard with a map of devices with
their tag and location through the website interface. Placing and modifying the
location of each device with a drag and drop configuration

## Requirements

- Python 3.6+
- Flask
- requests
- pydbus
- PyGObject

## Installation

1. Clone the repository or Pull latest:
    ```sh
    git clone https://github.com/scriche/Bluepath
    cd Bluepath

    or

    cd Bluepath
    git pull
    ```

2. Install the required dependencies:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

### Server

1. Run the server:
    ```sh
    python bluepathserver.py
    ```

2. Enter the server port when prompted.

The server will start listening for UDP packets and will also run a Flask web server to display the logs.

## Viewing Web Interface

Open a web browser and navigate to `http://<server_ip>:8080` to view the logs.

### Client

1. Run the client:
    ```sh
    python bluepathclient.py
    ```

2. Enter the server IP address and port when prompted.

The client will continuously send the log file to the server every 3 seconds.

### Bluetooth Device Monitoring

1. Run the Bluetooth device monitoring script:
    ```sh
    python bluepath.py
    ```

This script will monitor nearby Bluetooth devices and log their information to `bluepath.log`.
