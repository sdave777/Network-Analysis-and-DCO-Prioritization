# Null Hypothesis (H0): There is no significant difference in the likelihood of malicious traffic between TCP and UDP traffic.
# Alternative Hypothesis (H1): Eliminating TCP traffic and keeping only UDP traffic will reduce the likelihood of malicious traffic.

import pandas as pd
from joblib import load
import ipaddress
from scipy.stats import ttest_ind

# Load the dataset
file_path = './data/IOTNet24_IDS.csv'
data = pd.read_csv(file_path)

# Load the trained model and label encoders
model = load('./data/random_forest_model.joblib')
proto_encoder = load('./data/proto_encoder.joblib')
conn_state_encoder = load('./data/conn_state_encoder.joblib')

# Function to convert IP address to an integer
def ip_to_int(ip):
    return int(ipaddress.IPv4Address(ip))

# Data preprocessing
data.ffill(inplace=True)
data['byte_rate'] = (data['orig_bytes'] + data['resp_bytes']) / data['duration']
data['id.orig_h'] = data['id.orig_h'].apply(ip_to_int)
data['id.resp_h'] = data['id.resp_h'].apply(ip_to_int)
data['proto'] = proto_encoder.transform(data['proto'])
data['conn_state'] = conn_state_encoder.transform(data['conn_state'])

# Features for prediction
features = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'byte_rate']

# Predict malicious likelihood for the entire dataset
data['malicious_likelihood'] = model.predict_proba(data[features])[:, 1]

# Filter data for TCP and UDP traffic
tcp_data = data[data['proto'] == proto_encoder.transform(['tcp'])[0]]
udp_data = data[data['proto'] == proto_encoder.transform(['udp'])[0]]

# Calculate mean malicious likelihood for TCP and UDP traffic
mean_tcp_likelihood = tcp_data['malicious_likelihood'].mean()
mean_udp_likelihood = udp_data['malicious_likelihood'].mean()

# Perform hypothesis test (t-test)
t_stat, p_value = ttest_ind(tcp_data['malicious_likelihood'], udp_data['malicious_likelihood'])

# import ace_tools as tools; tools.display_dataframe_to_user(name="Malicious Likelihood Analysis for TCP vs UDP", dataframe=pd.DataFrame({
#     'Mean TCP Malicious Likelihood': [mean_tcp_likelihood],
#     'Mean UDP Malicious Likelihood': [mean_udp_likelihood],
#     'T-Statistic': [t_stat],
#     'P-Value': [p_value]
# }))

print("mean udp probability: ", mean_tcp_likelihood, "mean tcp probability: ", mean_udp_likelihood, "t-stat: ", t_stat, "p-value: ", p_value)
