
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