from scapy.all import sniff, IP
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

class NetworkMonitor:
    def __init__(self):
        self.model = RandomForestClassifier()
        # Load pre-trained model using CICIDS2017 dataset
        
    def packet_handler(self, packet):
        if IP in packet:
            features = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'length': len(packet)
            }
            prediction = self.model.predict(pd.DataFrame([features]))
            if prediction == 1:
                print(f"Anomalous traffic detected: {features}")

def start_monitoring(interface='eth0'):
    monitor = NetworkMonitor()
    sniff(iface=interface, prn=monitor.packet_handler, store=0)