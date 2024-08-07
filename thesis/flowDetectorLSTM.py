import numpy as np
import pandas as pd
import joblib
import keras
from keras.models import load_model
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns

class FlowDetector:
    def __init__(self):
        self.model = load_model('models/model_flow_lstm.h5')
        self.scaler = joblib.load('thesis/models/flow_scaler.gz')  # Adjust path as necessary

    def process_flow_data(self, data_file):
        df = pd.read_csv(data_file)
        # Assume the same preprocessing steps as during training
        X = df.values[:, :-1]
        X_scaled = self.scaler.transform(X)
        return X_scaled

    def detect_flow(self, data_file):
        print("Detecting flow anomalies...")
        features = self.process_flow_data(data_file)
        predictions = self.model.predict(features)
        return predictions

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Flow detector')
    parser.add_argument('--data', required=True, help='Flow data file to parse')
    args = parser.parse_args()

    detector = FlowDetector()
    predictions = detector.detect_flow(args.data)
    print(f"Predictions: {predictions}")
