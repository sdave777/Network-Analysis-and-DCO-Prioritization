import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from joblib import dump
import ipaddress
import numpy as np
import matplotlib.pyplot as plt

# Function to convert IP address to an integer
def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))

# Load the dataset
file_path = './data/IOTNet24_IDS.csv'
data = pd.read_csv(file_path)

# Data Cleaning
data.ffill(inplace=True)

# Feature Engineering
data['byte_rate'] = (data['orig_bytes'] + data['resp_bytes']) / data['duration']
data['id.orig_h'] = data['id.orig_h'].apply(ip_to_int)
data['id.resp_h'] = data['id.resp_h'].apply(ip_to_int)

# Label Encoding
proto_encoder = LabelEncoder()
conn_state_encoder = LabelEncoder()

# Ensure all possible values are seen by the encoder
all_conn_states = ['S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH']
proto_encoder.fit(pd.concat([data['proto'], pd.Series(['tcp'])]).unique())
conn_state_encoder.fit(all_conn_states)

data['proto'] = proto_encoder.transform(data['proto'])
data['conn_state'] = conn_state_encoder.transform(data['conn_state'])
data['label'] = LabelEncoder().fit_transform(data['label'])

# Model Training
features = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'byte_rate']
target = 'label'
X = data[features]
y = data[target]
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))
print('Accuracy:', accuracy_score(y_test, y_pred))

# Predict probabilities
y_prob = model.predict_proba(X_test)[:, 1]

# Add probabilities to the test set
X_test['probability'] = y_prob

# Get top 5 most likely malicious `id.resp_h` IPs
top_5_resp_ips = X_test.groupby('id.resp_h')['probability'].max().sort_values(ascending=False).head(10).reset_index()

# Convert IPs back to string format
top_5_resp_ips['id.resp_h'] = top_5_resp_ips['id.resp_h'].apply(lambda x: str(ipaddress.IPv4Address(x)))
print("Top 10 most likely malicious `id.resp_h` IP addresses:")
print(top_5_resp_ips)

# Plotting
plt.figure(figsize=(10, 6))
plt.barh(top_5_resp_ips['id.resp_h'], top_5_resp_ips['probability'], color='skyblue')
plt.xlabel('Probability')
plt.ylabel('IP Address')
plt.title('Top 10 IP Addresses, Most Likely to be Malicious')
plt.gca().invert_yaxis()
plt.show()