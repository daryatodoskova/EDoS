import argparse
import os
import sys
import logging
from scapy.all import *
from keras.models import load_model
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def process_pcap(file_name, client_address='172.16.1.3'):
    logging.info(f'Opening {file_name}...')
    
    count = 0
    data = [[]]
    nb_of_in_pkt = 0
    time = []
    nb_of_bytes = 0
    
    for pkt_data, pkt_metadata in RawPcapReader(file_name):
        count += 1
        
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields:
            continue

        if ether_pkt.type != 0x0800:
            continue

        ip_pkt = ether_pkt[IP]
        if ip_pkt.src != client_address:
            nb_of_in_pkt += 1
            if nb_of_in_pkt == 1:
                first_pkt_timestamp = ip_pkt.time
                previous_pkt_timestamp = first_pkt_timestamp
                continue
            current_pkt_timestamp = ip_pkt.time
            time_bw_2_pkt = current_pkt_timestamp - previous_pkt_timestamp
            previous_pkt_timestamp = current_pkt_timestamp
            time.append(time_bw_2_pkt)
            nb_of_bytes += ip_pkt.len
    
    data[0].append(nb_of_in_pkt)
    data[0].append(nb_of_bytes)
    
    sum_of_time_bw_2_pkt = sum(time)
    avr_time_bw_2_pkt = sum_of_time_bw_2_pkt / len(time) if time else 0
    data[0].append(avr_time_bw_2_pkt)
    
    return data, ip_pkt.src

def load_model_and_scaler(model_path, scaler_path):
    model = load_model(model_path)
    scaler = joblib.load(scaler_path)
    return model, scaler

def flow_detector(data, model):
    flow_type = (model.predict(data) > 0.5).astype(int)
    return flow_type

def main():
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
    args = parser.parse_args()
    
    file_name = args.pcap
    if not os.path.isfile(file_name):
        logging.error(f'"{file_name}" does not exist')
        sys.exit(-1)
    
    model, scaler = load_model_and_scaler('models/model_flow.h5', 'models/flow_scaler.gz')
    
    flow_features, ip_address = process_pcap(file_name)
    flow_features = scaler.transform(flow_features)
    
    is_abnormal_flow = flow_detector(flow_features, model)
    
    if is_abnormal_flow:
        logging.info(f'"{ip_address}" is an attacker')
    else:
        logging.info(f'"{ip_address}" is a normal user')

if __name__ == '__main__':
    main()
