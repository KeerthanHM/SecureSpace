import pandas as pd
from sklearn.ensemble import IsolationForest
import scapy.all as scapy

# Function to extract features froimport scapy.all as scapy
import pandas as pd
from sklearn.ensemble import IsolationForest

# Function to extract features from the packet
def extract_features(packet):
    # Implement your feature extraction logic here
    pass

# Load the pcap file
packets = scapy.rdpcap(r'C:\Users\keert\Desktop\hi.pcapng')

# Initialize feature matrix X
X = []

# Extract features from the packets
for packet in packets:
    # Extract desired features from the packet and append to X
    features = extract_features(packet)
    X.append(features)

# Convert X to a DataFrame
data = pd.DataFrame(X, columns=['feature1', 'feature2', 'feature3'])  # Replace 'feature1', 'feature2', 'feature3' with actual feature names

# Create and train the Isolation Forest model
model = IsolationForest(contamination=0.05)  # Adjust the contamination parameter as needed
model.fit(data)

# Make predictions on the data
predictions = model.predict(data)

# Identify the anomalous instances
anomalies = data[predictions == -1]

# Print the anomalous instances
print("Anomalous instances:")
print(anomalies)

# Extract the IP/MAC address of the anomalous systems
anomalous_ips = anomalies['feature1']  # Replace 'feature1' with the actual column name
anomalous_macs = anomalies['feature2']  # Replace 'feature2' with the actual column name

# Print the anomalous IP/MAC addresses
print("Anomalous IP addresses:")
print(anomalous_ips.unique())

print("Anomalous MAC addresses:")
print(anomalous_macs.unique())
m the packet
def extract_features(packet):
    # Implement your feature extraction logic here
    pass

# Load the pcap file
packets = scapy.rdpcap(r'C:\Users\keert\Desktop\hi.pcapng')

# Initialize feature matrix X
X = []

# Extract features from the packets
for packet in packets:
    # Extract desired features from the packet and append to X
    features = extract_features(packet)
    X.append(features)

# Convert X to a DataFrame
data = pd.DataFrame(X, columns=['feature1', 'feature2', 'feature3'])  # Replace 'feature1', 'feature2', 'feature3' with actual feature names

# Create and train the Isolation Forest model
model = IsolationForest(contamination=0.05)  # Adjust the contamination parameter as needed
model.fit(data)

# Make predictions on the data
predictions = model.predict(data)

# Identify the anomalous instances
anomalies = data[predictions == -1]

# Print the anomalous instances
print("Anomalous instances:")
print(anomalies)

# Extract the IP/MAC address of the anomalous systems
anomalous_ips = anomalies['feature1']  # Replace 'feature1' with the actual column name
anomalous_macs = anomalies['feature2']  # Replace 'feature2' with the actual column name

# Print the anomalous IP/MAC addresses
print("Anomalous IP addresses:")
print(anomalous_ips.unique())

print("Anomalous MAC addresses:")
print(anomalous_macs.unique())


# Load the preprocessed data
data = pd.read_csv('preprocessed_data.csv')

# Perform one-hot encoding for the IP addresses
data = pd.get_dummies(data, columns=['src_ip', 'dst_ip'])

# Initialize and fit the Isolation Forest model
model = IsolationForest()
model.fit(data)

# Make predictions on the data
predictions = model.predict(data)

# Get the indices of the anomalies
anomaly_indices = data.index[predictions == -1]

# Retrieve the IP addresses of the anomalies
anomaly_ips = data.iloc[anomaly_indices, :][['src_ip', 'dst_ip']]

# Print the IP addresses of the anomalies
print("Anomalous IP addresses:")
print(anomaly_ips)

def extract_features(packet):
    features = []
    
    # Check if the packet has an IP layer
    if packet.haslayer(scapy.IP):
        # Extract IP-related features
        ip = packet[scapy.IP]
        features.append(ip.src)  # Source IP address
        features.append(ip.dst)  # Destination IP address
        features.append(ip.len)  # IP packet length
    else:
        features.extend([0, 0, 0])  # Pad with zeros
    
    # Check if the packet has an Ethernet layer
    if packet.haslayer(scapy.Ether):
        # Extract Ethernet-related features
        eth = packet[scapy.Ether]
        features.append(eth.src)  # Source MAC address
        features.append(eth.dst)  # Destination MAC address
    else:
        features.extend([0, 0])  # Pad with zeros
    
    # Add more features as needed
    
    return features
