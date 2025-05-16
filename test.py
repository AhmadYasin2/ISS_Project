import time
import random
import hashlib
import argparse
import json
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from scapy.all import IP, TCP, sniff
from sklearn.ensemble import IsolationForest
from Crypto.Protocol.SecretSharing import Shamir
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

def GeneratePacketData(n_packets=1000):
    packets = []
    for i in range(n_packets):
        size = random.randint(50, 1500 ) 
        src_ip = f"192.168.1.{random.randint(1, 255)}"
        dest_ip = f"192.168.1.{random.randint(1, 255)}"
        is_malicious = random.random() < 0.1
        device_type = random.choice(['mobile', 'desktop'])
        content = "malicious" if is_malicious else "benign"
        packets.append([size, src_ip, dest_ip, is_malicious, device_type, content])
    return pd.DataFrame(packets, columns=['size', 'src_ip', 'dest_ip', 'is_malicious', 'device_type', 'content'])

def capture_real_packets(count=10):
    try:
        packets = sniff(filter="tcp", count=count, timeout=10)
        data = []
        for pkt in packets:
            if IP in pkt and TCP in pkt:
                size = len(pkt)
                src_ip = pkt[IP].src
                dest_ip = pkt[IP].dst
                content = str(pkt[TCP].payload)
                data.append([size, src_ip, dest_ip, False, 'desktop', content])
        return pd.DataFrame(data, columns=['size', 'src_ip', 'dest_ip', 'is_malicious', 'device_type', 'content'])
    except Exception as e:
        print(f"Error capturing packets: {e}. Falling back to simulated data.")
        return GeneratePacketData(n_packets=count)

def encrypt_aes(data, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16))
    encryptor = cipher.encryptor()
    padded_data = data + b'\0' * (16 - len(data) % 16)
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes(encrypted_data, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(b'\0' * 16))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted.rstrip(b'\0')

def encrypt_chacha20(data, key):
    nonce = b'\0' * 16  
    cipher = Cipher(ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def decrypt_chacha20(encrypted_data, key):
    nonce = b'\0' * 16
    cipher = Cipher(ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def generate_kyber_key():
    return hashlib.sha256(str(random.randint(0, 1000000)).encode()).digest()

def rotate_key(current_key, packet_count, max_packets=100):
    if packet_count % max_packets == 0:
        return generate_kyber_key()
    return current_key

def detect_anomalies(packets):
    model = IsolationForest(contamination=0.1, random_state=42)
    ip_counts = packets['src_ip'].value_counts().to_dict()
    packets['ip_freq'] = packets['src_ip'].map(ip_counts)
    packets['content_len'] = packets['content'].str.len()
    features = packets[['size', 'ip_freq', 'content_len']].values
    packets['risk_score'] = model.fit_predict(features)
    packets['risk_score'] = np.where(packets['risk_score'] == -1, 0.8, 0.2)
    return packets

def select_encryption_algorithm(packet, risk_score):
    if packet['device_type'] == 'mobile':
        return 'chacha20'
    if risk_score > 0.7:
        return 'kyber'
    return 'aes256'

def deep_packet_inspection(packet):
    malicious_signatures = ['malicious', 'xss', 'sql']
    return any(sig in packet['content'].lower() for sig in malicious_signatures)

def intrusion_prevention(packet, is_malicious):
    return 'block' if is_malicious else 'allow'

def honeypot_response(packet, risk_score):
    if risk_score > 0.5:
        fake_port = random.randint(1000, 9999)
        return f"Dynamic fake response: Port {fake_port} for {packet['src_ip']}"
    return f"Standard fake response for {packet['src_ip']}"

def store_log(log_data, log_buffer, log_file='sdes_logs.json'):
    try:
        
        sha1_hash = hashlib.sha1(log_data).digest() 
        secret = sha1_hash[:16]  
        shares = Shamir.split(3, 5, secret)
        ipfs_nodes = [f"node_{i}" for i in range(5)]
        distributed_logs = {node: share[1].hex() for node, share in zip(ipfs_nodes, shares)}
        
      
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'log_hash': secret.hex(),
            'distributed_nodes': distributed_logs
        }
        log_buffer.append(log_entry)
        return distributed_logs
    except Exception as e:
        print(f"Error storing log: {e}")
        return {}


def reconstruct_log(shares):
    try:
      
        byte_shares = [(i+1, bytes.fromhex(share)) for i, share in enumerate(shares[:3])]
        secret = Shamir.combine(byte_shares)
        return secret.hex()
    except Exception as e:
        print(f"Error reconstructing log: {e}")
        return None


def run_sdes_simulation(mode='full'):
    random.seed(42)  
    if mode == 'real':
        packets = capture_real_packets(count=10)
    else:
        packets = GeneratePacketData(n_packets=100 if mode == 'light' else 1000)
    
    current_key = generate_kyber_key()
    packet_count = 0
    results = {
        'encrypted': 0, 'anomalies_detected': 0, 'dpi_flagged': 0,
        'honeypot_triggered': 0, 'blocked': 0, 'decrypted_success': 0
    }
    stored_logs = []
    log_buffer = []  

    start_time = time.time()
    packets = detect_anomalies(packets)
    results['anomalies_detected'] = len(packets[packets['risk_score'] == 0.8])
    
    for _, packet in packets.iterrows():
        packet_count += 1
        current_key = rotate_key(current_key, packet_count)
        
     
        dpi_malicious = deep_packet_inspection(packet)
        high_risk = packet['risk_score'] > 0.7
        is_malicious = dpi_malicious and high_risk  
        if is_malicious:
            results['dpi_flagged'] += 1
            results['honeypot_triggered'] += 1
            results['blocked'] += 1
            action = intrusion_prevention(packet, True)
            if action == 'block':
                continue
        
   
        algo = select_encryption_algorithm(packet, packet['risk_score'])
        data = str(packet).encode()
        encrypted_data = None
        
        if algo == 'aes256':
            encrypted_data = encrypt_aes(data, current_key)
            decrypted_data = decrypt_aes(encrypted_data, current_key)
        elif algo == 'chacha20':
            encrypted_data = encrypt_chacha20(data, current_key)
            decrypted_data = decrypt_chacha20(encrypted_data, current_key)
        else: 
            encrypted_data = hashlib.sha256(data).digest()
            decrypted_data = data  
        
        results['encrypted'] += 1
        if decrypted_data == data:
            results['decrypted_success'] += 1
        

        if packet['risk_score'] > 0.5:
            honeypot_response(packet, packet['risk_score'])
            results['honeypot_triggered'] += 1
        

        log_data = hashlib.sha256(encrypted_data).digest()
        distributed_logs = store_log(log_data, log_buffer)
        stored_logs.append(distributed_logs)
    

    try:
        with open('sdes_logs.json', 'a') as f:
            for entry in log_buffer:
                json.dump(entry, f)
                f.write('\n')
    except Exception as e:
        print(f"Error writing logs to file: {e}")
    
 
    if stored_logs:
        sample_shares = list(stored_logs[0].values())[:3]
        reconstructed = reconstruct_log(sample_shares)
        if reconstructed:
            print(f"Shamir Reconstruction Successful: {reconstructed}")

    execution_time = time.time() - start_time
    return results, execution_time, packets, stored_logs


def plot_results(results, packets):
    plt.figure(figsize=(10, 6))
    plt.bar(results.keys(), results.values(), color='skyblue')
    plt.title('SDES Simulation Results')
    plt.ylabel('Count')
    plt.savefig('sdes_results_full.png')
    
    plt.figure(figsize=(10, 6))
    plt.hist(packets['risk_score'], bins=20, color='lightgreen')
    plt.title('Packet Risk Score Distribution')
    plt.xlabel('Risk Score')
    plt.ylabel('Frequency')
    plt.savefig('risk_score_distribution_full.png')


def main():
    parser = argparse.ArgumentParser(description='SDES Simulation')
    parser.add_argument('--mode', choices=['full', 'light', 'real'], default='full',
                        help='Simulation mode: full (1000 packets), light (100 packets), or real (Scapy capture)')
    args = parser.parse_args()
    
    results, exec_time, packets, stored_logs = run_sdes_simulation(mode=args.mode)
    plot_results(results, packets)
    print(f"Simulation Mode: {args.mode}")
    print(f"Simulation Results: {results}")
    print(f"Execution Time: {exec_time:.2f} seconds")
    print(f"Sample Distributed Log: {stored_logs[0] if stored_logs else 'None'}")

if __name__ == '__main__':
    main()