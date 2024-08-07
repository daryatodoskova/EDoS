import threading
import time
import os
import sys
import signal
from flask import Flask, request, render_template_string
import pyshark
from thesis.periodDetector import PeriodDetector, Config
import uuid
from thesis.flowDetectorLSTM import FlowDetector


#simulates a flask server, if success then returns Website Status: Online. 
# as soon as the server is started, it triggers a second thread.
# this second thread captures a packet on an interval of 10 seconds (every 10 sec it calls periodDetector.py to check if attack/benign )

app = Flask(__name__)

detector = PeriodDetector()

flow_detector = FlowDetector()

# Request filter class
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



#  * Running on http://127.0.0.1:3333
#  * Running on http://192.168.10.115:3333

@app.route('/')
def index():
    client_ip = request.remote_addr    
    return render_template_string('<h1>Website Status: Online</h1>')

def signal_handler(sig, frame):
    print('Exiting gracefully...')
    capture.close()  # Properly close the capture when exiting
    detector.close()  # Ensure SparkContext is closed
    sys.exit(0)


def start_capture():
    global capture
    while True:
        #allowed_ips = ['192.168.64.4', '192.168.64.5', '192.168.64.6']  # List of allowed IPs
        
        capture_file = os.path.join(os.getcwd(), f'{uuid.uuid4()}.pcap')
        capture = pyshark.LiveCapture(interface='bridge100', output_file=capture_file)
        capture.sniff(timeout=10)
        print("Analyzing traffic...")
        is_abnormal = detector.detect_period(capture_file)
        print(f"Is abnormal: {is_abnormal}")
        if is_abnormal:
            print("Period detected. Analyzing flow data...")
            flow_file = 'path_to_flow_data_file.csv'  # Ensure you have a flow data file to analyze
            flow_predictions = flow_detector.detect_flow(flow_file)
            print(f"Flow Predictions: {flow_predictions}")

        os.remove(capture_file)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start the packet capture in a separate thread to avoid blocking Flask
    threading.Thread(target=start_capture).start()
    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=3333, use_reloader=False)