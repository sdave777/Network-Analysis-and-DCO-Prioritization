import pandas as pd
from fastapi import FastAPI, Query, HTTPException
from joblib import load
import ipaddress
from scipy.stats import ttest_ind

# Initialize FastAPI app
app = FastAPI()

# Load the trained model and label encoders
try:
    model = load('./data/logistic_regression_model.joblib')
    proto_encoder = load('./data/proto_encoder.joblib')
    conn_state_encoder = load('./data/conn_state_encoder.joblib')
except FileNotFoundError:
    raise HTTPException(status_code=500, detail="Model or encoder files not found.")

# Function to convert IP address to an integer
def ip_to_int(ip):
    try:
        return int(ipaddress.IPv4Address(ip))
    except ipaddress.AddressValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format.")

# Define a default set of values for other features
default_values = {
    'id_resp_p': 80,
    'id_orig_h': '192.168.1.1',
    'id_orig_p': 12345,
    'proto': 'tcp',
    'duration': 1.0,
    'orig_bytes': 100,
    'resp_bytes': 100,
    'conn_state': 'SF'
}

# Endpoint to predict malicious likelihood
@app.get("/predict")
def predict(ip: str = Query(..., description="Responding IP address")):
    try:
        # Convert request data to DataFrame
        data = {
            'id.resp_h': ip_to_int(ip),
            'id.resp_p': default_values['id_resp_p'],
            'id.orig_h': ip_to_int(default_values['id_orig_h']),
            'id.orig_p': default_values['id_orig_p'],
            'proto': default_values['proto'],
            'duration': default_values['duration'],
            'orig_bytes': default_values['orig_bytes'],
            'resp_bytes': default_values['resp_bytes'],
            'conn_state': default_values['conn_state']
        }
        df = pd.DataFrame([data])

        # Preprocess data
        df['proto'] = proto_encoder.transform(df['proto'])
        df['conn_state'] = conn_state_encoder.transform(df['conn_state'])
        df['byte_rate'] = (df['orig_bytes'] + df['resp_bytes']) / df['duration']

        # Features
        features = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'byte_rate']
        
        # Predict the likelihood of malicious activity
        prediction = model.predict_proba(df[features])[0, 1]
        
        return {"id_resp_h": ip, "malicious_likelihood": prediction}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

# Endpoint for hypothesis test on duration with user-provided threshold
@app.get("/hypothesis/duration")
def hypothesis_duration(threshold: float = Query(..., description="Duration threshold to distinguish long and short connections")):
    try:
        # Load the dataset
        file_path = './data/IOTNet24_IDS.csv'
        data = pd.read_csv(file_path)

        # Data preprocessing
        data.ffill(inplace=True)
        data['byte_rate'] = (data['orig_bytes'] + data['resp_bytes']) / data['duration']
        data['id.orig_h'] = data['id.orig_h'].apply(ip_to_int)
        data['id.resp_h'] = data['id.resp_h'].apply(ip_to_int)
        data['proto'] = proto_encoder.transform(data['proto'])
        data['conn_state'] = conn_state_encoder.transform(data['conn_state'])

        # Create a binary feature for long duration based on user-provided threshold
        data['long_duration'] = data['duration'] > threshold

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

        # Interpretation of results
        if p_value < 0.05:
            result = "Alternative hypothesis supported: There is a significant difference in malicious likelihood between long and short duration connections."
        else:
            result = "Null hypothesis supported: There is no significant difference in malicious likelihood between long and short duration connections."

        return {
            "threshold_duration": threshold,
            "mean_long_duration_likelihood": mean_long_duration_likelihood,
            "mean_short_duration_likelihood": mean_short_duration_likelihood,
            "t_statistic": t_stat,
            "p_value": p_value,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

# Endpoint for hypothesis test on protocol with user-provided protocol type
@app.get("/hypothesis/protocol")
def hypothesis_protocol(protocol: str = Query(..., description="Protocol to test (udp or tcp)")):
    try:
        # Load the dataset
        file_path = './data/IOTNet24_IDS.csv'
        data = pd.read_csv(file_path)

        # Data preprocessing
        data.ffill(inplace=True)
        data['byte_rate'] = (data['orig_bytes'] + data['resp_bytes']) / data['duration']
        data['id.orig_h'] = data['id.orig_h'].apply(ip_to_int)
        data['id.resp_h'] = data['id.resp_h'].apply(ip_to_int)
        data['proto'] = proto_encoder.transform(data['proto'])
        data['conn_state'] = conn_state_encoder.transform(data['conn_state'])

        # Ensure the provided protocol is valid
        if protocol not in ['udp', 'tcp']:
            raise HTTPException(status_code=400, detail="Invalid protocol. Please choose either 'udp' or 'tcp'.")

        # Encode the provided protocol
        protocol_encoded = proto_encoder.transform([protocol])[0]

        # Filter data for the specified protocol and other protocols
        protocol_data = data[data['proto'] == protocol_encoded]
        other_protocol_data = data[data['proto'] != protocol_encoded]

        # Features for prediction
        features = ['id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'proto', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'byte_rate']

        # Predict malicious likelihood for the specified protocol and other protocols
        protocol_data['malicious_likelihood'] = model.predict_proba(protocol_data[features])[:, 1]
        other_protocol_data['malicious_likelihood'] = model.predict_proba(other_protocol_data[features])[:, 1]

        # Calculate mean malicious likelihood for the specified protocol and other protocols
        mean_protocol_likelihood = protocol_data['malicious_likelihood'].mean()
        mean_other_protocol_likelihood = other_protocol_data['malicious_likelihood'].mean()

        # Perform hypothesis test (t-test)
        t_stat, p_value = ttest_ind(protocol_data['malicious_likelihood'], other_protocol_data['malicious_likelihood'])

        # Interpretation of results
        if p_value < 0.05:
            if t_stat > 0:
                result = f"{protocol.upper()} is significantly more likely to be malicious than other protocols."
            else:
                result = f"{protocol.upper()} is significantly less likely to be malicious than other protocols."
        else:
            result = f"{protocol.upper()} is not significantly more likely to be malicious than other protocols."

        return {
            "protocol": protocol,
            "mean_protocol_likelihood": mean_protocol_likelihood,
            "mean_other_protocol_likelihood": mean_other_protocol_likelihood,
            "t_statistic": t_stat,
            "p_value": p_value,
            "result": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")

# To run the app, use the command:
# uvicorn API:app