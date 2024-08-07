import os
import joblib
import numpy as np
import pandas as pd
import pyshark
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler

class Config:
    MODEL_PATH = '../models/flow_model_lstm.h5'
    SCALER_PATH = '../models/flow_scaler.gz'

class FlowDetector:
    def __init__(self):
        self.scaler = joblib.load(Config.SCALER_PATH)
        self.model = load_model(Config.MODEL_PATH)
        print("LSTM model loaded successfully.")

    def process_pcap(self, pcap_file):
        capture = pyshark.FileCapture(pcap_file)
        flow_features = []

        for packet in capture:
            try:
                if 'IP' in packet:
                    src = packet.ip.src
                    dst = packet.ip.dst
                    protocol = packet.transport_layer
                    length = packet.length

                    if protocol == 'TCP' or protocol == 'UDP':
                        sport = packet[packet.transport_layer].srcport
                        dport = packet[packet.transport_layer].dstport
                    else:
                        sport = 0
                        dport = 0

                    flow_features.append([src, dst, sport, dport, protocol, length])
            except AttributeError as e:
                continue

        capture.close()
        return pd.DataFrame(flow_features, columns=['src', 'dst', 'sport', 'dport', 'protocol', 'length'])

    def detect_anomalies(self, pcap_file):
        df = self.process_pcap(pcap_file)
        if df.empty:
            print("No flows to process.")
            return []

        X = df[['src', 'dst', 'sport', 'dport', 'length']].values
        X_scaled = self.scaler.transform(X)
        X_reshaped = X_scaled.reshape((X_scaled.shape[0], 1, X_scaled.shape[1]))

        predictions = self.model.predict(X_reshaped)
        anomalies = (predictions > 0.5).astype("int32").flatten()

        return df[anomalies == 1]

if __name__ == "__main__":
    detector = FlowDetector()
    pcap_file = 'path_to_pcap_file.pcap'  # Update with actual pcap file path
    anomalies = detector.detect_anomalies(pcap_file)

    if not anomalies.empty:
        print("Anomalous flows detected:")
        print(anomalies)
    else:
        print("No anomalous flows detected.")
