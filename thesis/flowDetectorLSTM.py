import argparse
import joblib
import numpy as np
import pandas as pd
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
import pyshark

class Config:
    MODEL_PATH = 'thesis/models/model_flow.h5'
    SCALER_PATH = 'thesis/models/flow_scaler.gz'

class FlowDetector:
    def __init__(self):
        # Load the scaler and model
        self.scaler = joblib.load(Config.SCALER_PATH)
        self.model = load_model(Config.MODEL_PATH)
        print("Model and scaler loaded successfully.")

    def extract_features(self, pcap_file):
        # Dummy feature extraction function, replace with actual extraction logic
        print(f"Extracting features from {pcap_file}...")
        features = []

        # Example of extracting features
        cap = pyshark.FileCapture(pcap_file)
        for pkt in cap:
            ip_src = pkt.ip.src
            ip_dst = pkt.ip.dst
            # Add more features as needed
            features.append([ip_src, ip_dst])
        
        cap.close()
        return features

    def detect_flow(self, features):
        # Prepare data for model prediction
        features = np.array(features)
        normalized_features = self.scaler.transform(features)
        
        # Predict using the model
        predictions = self.model.predict(normalized_features)
        
        # Determine if the flow is abnormal
        for i, prediction in enumerate(predictions):
            if prediction > 0.5:
                print(f"Flow from {features[i][0]} is abnormal.")
            else:
                print(f"Flow from {features[i][0]} is normal.")
                
    def process_pcap(self, pcap_file):
        features = self.extract_features(pcap_file)
        if features:
            self.detect_flow(features)
        else:
            print("No features extracted.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Flow Detection using LSTM model.")
    parser.add_argument("--pcap", required=True, help="Path to the pcap file.")
    args = parser.parse_args()

    if not os.path.isfile(args.pcap):
        print(f'File "{args.pcap}" does not exist.')
        sys.exit(-1)

    detector = FlowDetector()
    detector.process_pcap(args.pcap)
