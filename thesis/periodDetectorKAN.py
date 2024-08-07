import argparse
import os
import sys
import pandas as pd
import keras
import numpy as np
import joblib
from tqdm import tqdm
from pyspark import SparkContext
import onnxruntime as ort
from scapy.all import Ether, IP, TCP, UDP, RawPcapReader
import logging
logging.getLogger('werkzeug').setLevel(logging.ERROR)

class Config:
    SERVER_ADDRESS = '192.168.64.1' #'192.168.10.115'  
    MODEL_PATH = 'thesis/training/period_model_kan.onnx'
    SCALER_PATH = 'thesis/models/period_scaler.gz'
    DISPLAY_FILTER = 'http'

class PeriodDetector:
    def __init__(self):
        self.scaler = joblib.load(Config.SCALER_PATH)
        print("Loading ONNX model.")
        self.session = ort.InferenceSession(Config.MODEL_PATH)
        print("ONNX model loaded successfully.")
        self.sc = SparkContext("local", "PCAP Analysis")
        print("SparkContext initialized.")

    def process_pcap(self, pcap_file):
        #print('Opening {}...'.format(fileName))

        count = 0
        #tuple of general packets
        tuplePKt=[]
        #tuple of SYN packets
        tupleSyn=[]
        #tuple of SYN-ACK packets
        tupleSynAck=[]
        #tuple of ACK packets
        tupleAck=[]
        udpPkt = []
        data=[[]]
        #number of outgoing packets
        nbOfOutPkt=0
        for (pktData, pktMetadata,) in tqdm(RawPcapReader(pcap_file)):
            count += 1
            
            etherPkt = Ether(pktData)
            if 'type' not in etherPkt.fields:
                continue
            
            if etherPkt.type != 0x0800:
                continue
            
            ipPkt = etherPkt[IP]
            if ipPkt.src == Config.SERVER_ADDRESS:
                nbOfOutPkt += 1
            
            if ipPkt.proto == 6:  # TCP packets
                tcpPkt = ipPkt[TCP]
                tpTCP = (ipPkt.src, ipPkt.dst, tcpPkt.sport, tcpPkt.dport, "TCP")
                tuplePKt.append(tpTCP)
                
                if 'S' in str(tcpPkt.flags) and 'A' not in str(tcpPkt.flags):
                    tpTcpSyn = (ipPkt.src, ipPkt.dst, tcpPkt.sport, tcpPkt.dport)
                    tupleSyn.append(tpTcpSyn)
                
                if 'S' in str(tcpPkt.flags) and 'A' in str(tcpPkt.flags):
                    tpTcpSynAck = (ipPkt.src, ipPkt.dst, tcpPkt.sport, tcpPkt.dport)
                    tupleSynAck.append(tpTcpSynAck)
                
                if 'A' in str(tcpPkt.flags) and 'S' not in str(tcpPkt.flags):
                    tpTcpAck = (ipPkt.src, ipPkt.dst, tcpPkt.sport, tcpPkt.dport)
                    tupleAck.append(tpTcpAck)
            
            elif ipPkt.proto == 17:  # UDP packets
                udpPkt = ipPkt[UDP]
                tpUDP = (ipPkt.src, ipPkt.dst, udpPkt.sport, udpPkt.dport, "UDP")
                tuplePKt.append(tpUDP)
            
            elif ipPkt.proto == 1:  # ICMP packets
                tpICMP = (ipPkt.src, ipPkt.dst, "ICMP")
                tuplePKt.append(tpICMP)
        
        print(f"Total packets processed: {count}")
        if not tuplePKt:
            print("No packets to process.")
            return None

        sc = self.sc
        try:
            countPkt = sc.parallelize(tuplePKt, numSlices=3).countByValue().values()
        except Exception as e:
            print(f"Error during parallelize: {e}")
            return None
        
        #print(tuplePKt)

        print(count)

        #Calculate Average length of flow
        countPktMap=sc.parallelize(countPkt, numSlices=3).map(lambda x:(x,1))
        countPktReduce=sc.parallelize(list(countPktMap.collect()), numSlices=3).reduce(lambda a,b:(a[0]+b[0],a[1]+b[1]))
        #print(countPktReduce)
        avrLengthFlow=0
        avrLengthFlow=countPktReduce[0]/countPktReduce[1]
        #print(avrLengthFlow)
        data[0].append(avrLengthFlow)
        #Caculate percentage of correlative flows
        nbOfCorrFlows=0
        # ICMP flows
        setofFlows = sc.parallelize(tuplePKt,numSlices=3).countByValue().keys()
        nbOfCorrIcmpFlows = 0
        for a in setofFlows:
            for b in setofFlows:
                if a[0] == b[1] and a[1]==b[0] and a[2]=="ICMP" and b[2]=="ICMP":
                    nbOfCorrIcmpFlows=nbOfCorrIcmpFlows+1
            #        print(a,b)
        #print(nbOfCorrIcmpFlows)
        # TCP flows
        setofSynFl=sc.parallelize(tupleSyn,numSlices=3).countByValue().keys()
        #print(setofSynFl)
        setofSynAckFl=sc.parallelize(tupleSynAck,numSlices=3).countByValue().keys()
        setofAckFl=list(sc.parallelize(tupleAck,numSlices=3).countByValue().keys())
        nbOfCorrTcpFlows = 0
        #for a in setofSynFl:
        #    for b in setofSynAckFl:
        #        for c in setofAckFl:
        #            if a[0]==b[1] and a[0]==c[0] and a[1]==b[0] and a[1]==c[1]: #and a[2]==b[3] and a[2]==c[2] and a[3]==b[2] and a[3]==c[3]:
        #               setofAckFl.remove(c)#we need to remove this flow to distigush the correlative flows in  connection validation time and normal time
        #               nbOfCorrTcpFlows=nbOfCorrTcpFlows+1
                    #print(setofAckFl)
        #nbOfCorrTcpFlows=nbOfCorrTcpFlows*2 #we need to mutiply to calculate the sum of correlative tcp flows
        for a in setofAckFl:
            for b in setofAckFl:
                if a[0]==b[1] and a[1]==b[0] and a[2]==b[3] and a[3]==b[2]:
                    nbOfCorrTcpFlows=nbOfCorrTcpFlows+1
        nbOfCorrFlows=0
        nbOfCorrFlows=(nbOfCorrIcmpFlows+nbOfCorrTcpFlows)/countPktReduce[1]
        data[0].append(nbOfCorrFlows)
        # Calculate one direction gerating speed
        odgs=0
        odgs=(countPktReduce[1]-nbOfCorrFlows)/5
        data[0].append(odgs)
        #Calculate ratio of Incoming and Outgoing packets
        nbInPkt=0
        nbInPkt=(count-nbOfOutPkt)
        data[0].append(nbInPkt)
        return data
        
        
    def detect_period(self, pcap_file):
        print("Detecting period...")
        # Extract features and convert to NumPy array
        features = self.process_pcap(pcap_file)
        
        # Check if features is a list and convert to NumPy array
        if isinstance(features, list):
            features = np.array(features)
        
        # Print feature shape for debugging
        print("Features shape:", features.shape)
        
        if features is None or features.size == 0:
            print("No features found")
            return False
        
        # Prepare input for ONNX model
        input_name = self.session.get_inputs()[0].name
        expected_shape = self.session.get_inputs()[0].shape
        print(f"Expected input shape: {expected_shape}")

        # Ensure features have the correct shape for normalization
        if len(features.shape) == 1:
            features = features.reshape(1, -1)  # Add batch dimension if needed
        
        # Normalize features
        normalized_features = self.scaler.transform(features)
        
        print("Normalized features shape:", normalized_features.shape)
        
        # Perform model inference
        prediction = self.session.run(None, {input_name: normalized_features.astype(np.float32)})[0]
        
        print(f"Prediction: {prediction}")
        return bool(prediction[0][0])  # Ensure it returns a boolean value

    
    def close(self):
        self.sc.stop()


"""
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='PCAP reader')
    parser.add_argument('--pcap', required=True, help='pcap file to parse')
    parser.add_argument('--filter', default=Config.DISPLAY_FILTER, help='display filter for capturing packets')
    args = parser.parse_args()

    Config.DISPLAY_FILTER = args.filter

    if not os.path.isfile(args.pcap):
        print(f'"{args.pcap}" does not exist', file=sys.stderr)
        sys.exit(-1)

    detector = PeriodDetector(args.pcap)
    is_abnormal = detector.detect_period()

    print(f"Is abnormal: {is_abnormal}")

"""