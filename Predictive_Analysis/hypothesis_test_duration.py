# The null hypothesis (H0): There is no significant difference in malicious likelihood between long and short duration connections.
# The alternative hypothesis (H1): There is a significant difference in malicious likelihood between long and short duration connections.

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

# Define a threshold for long duration (e.g., median duration)
threshold_duration = data['duration'].median()

# Create a binary feature for long duration
data['long_duration'] = data['duration'] > threshold_duration

# Features for prediction
features = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'byte_rate']

# Predict malicious likelihood for the entire dataset
data['malicious_likelihood'] = model.predict_proba(data[features])[:, 1]

# Filter data for long duration and short duration connections
long_duration_data = data[data['long_duration'] == True]
short_duration_data = data[data['long_duration'] == False]

# Calculate mean malicious likelihood for long and short duration connections
mean_long_duration_likelihood = long_duration_data['malicious_likelihood'].mean()
mean_short_duration_likelihood = short_duration_data['malicious_likelihood'].mean()

# Perform hypothesis test (t-test)
t_stat, p_value = ttest_ind(long_duration_data['malicious_likelihood'], short_duration_data['malicious_likelihood'])

# import ace_tools as tools; tools.display_dataframe_to_user(name="Malicious Likelihood Analysis for Long vs Short Duration Connections", dataframe=pd.DataFrame({
#     'Mean Long Duration Malicious Likelihood': [mean_long_duration_likelihood],
#     'Mean Short Duration Malicious Likelihood': [mean_short_duration_likelihood],
#     'T-Statistic': [t_stat],
#     'P-Value': [p_value]
# }))
print("mean long duration probability: ", mean_long_duration_likelihood, "mean short duration probability: ", mean_short_duration_likelihood, "t-stat: ", t_stat, "p-value: ", p_value)

