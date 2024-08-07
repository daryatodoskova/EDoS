from flask import Flask, request, render_template_string
import time
import pyshark
import signal
import sys
import os
import threading

app = Flask(__name__)

# Initialize a LiveCapture instance
capture = pyshark.LiveCapture(interface='bridge100', output_file=os.path.join(os.getcwd(), 'capture.pcap'))

def start_capture():
    allowed_ips = ['192.168.64.4', '192.168.64.5', '192.168.64.6']  # List of allowed IPs
    capture.sniff(timeout=50)
    for packet in capture.sniff_continuously(packet_count=5):
        if packet.ip.src in allowed_ips:
            print('Just arrived from allowed IP:', packet)
        else:
            print('Packet from disallowed IP:', packet)

# Start the packet capture in a separate thread to avoid blocking Flask
threading.Thread(target=start_capture).start()

class RequestFilter:
    def __init__(self, request_limit, time_window):
        self.request_count = 0
        self.last_checked_time = time.time()
        self.request_limit = request_limit
        self.time_window = time_window

    def is_request_allowed(self):
        current_time = time.time()
        
        if current_time - self.last_checked_time > self.time_window:
            self.request_count = 0
            self.last_checked_time = current_time
        
        self.request_count += 1
        
        if self.request_count > self.request_limit:
            return False
        
        return True

request_filter = RequestFilter(request_limit=15000, time_window=60)

@app.route('/')
def index():
    client_ip = request.remote_addr
    
    if not request_filter.is_request_allowed():
        return "Too many requests", 500
    
    print(f"Incoming request #{request_filter.request_count} from IP: {client_ip}")
    return render_template_string('<h1>Website Status: Online</h1>')

def signal_handler(sig, frame):
    print('Exiting gracefully...')
    capture.close()  # Properly close the capture when exiting
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3333)
