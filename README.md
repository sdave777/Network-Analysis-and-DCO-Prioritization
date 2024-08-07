# Network Analysis and DCO Prioritization

This repository contains code and resources for performing predictive analysis of malicious traffic using logs from a poorly configured Intrusion Detection System (IDS). The primary goal is to identify potential threats and test recommended mitigations quantitatively.

## Introduction
This project attempts a predictive analysis of malicious traffic using IDS logs. It further aims to test various mitigation strategies to enhance network security. The analyses include:
- Predicting the likelihood of malicious activity based on network traffic data.
- Performing hypothesis tests to determine the effectiveness of different security measures.

## Data
The dataset used in this project is `IOTNet24_IDS.csv`, which contains network traffic logs from an IDS. The dataset includes features such as IP addresses, ports, protocols, byte counts, and connection states.

## Setup
To set up the project, clone the repository and install the necessary dependencies:
```bash
git clone https://github.com/sdave777/Network-Analysis-and-DCO-Prioritization.git
cd Network-Analysis-and-DCO-Prioritization
pip install -r requirements.txt
```
## Usage

The project includes several scripts and a FastAPI application for interacting with the predictive model and performing hypothesis tests.

## Predict Malicious Likelihood

The FastAPI application provides an endpoint to predict the likelihood of malicious activity for a given IP address. To run the app:
```sh
uvicorn API:app
```
To predict malicious likelihood, send a GET request to /predict with the responding IP address as a query parameter (replace <RESPONDING_IP> with the IP address:

```sh
curl -X 'GET' \
  'http://127.0.0.1:8000/predict?ip=<RESPONDING_IP>' \
  -H 'accept: application/json'
 ```

Or use the Swagger User Interface at:

```url
http://127.0.0.1:8000/docs
```
## Hypothesis Tests

### Duration-Based Test

The /hypothesis/duration endpoint tests whether the duration of connections affects the likelihood of malicious activity.

To use this endpoint, send a GET request with a duration threshold:

```sh
curl -X 'GET' \
  'http://127.0.0.1:8000/hypothesis/duration?threshold=<DURATION_THRESHOLD>' \
  -H 'accept: application/json'
``` 
### Protocol-Based Test

The /hypothesis/protocol endpoint tests whether the type of protocol (TCP/UDP) affects the likelihood of malicious activity.

To use this endpoint, send a GET request specifying the protocol:

```sh
curl -X 'GET' \
  'http://127.0.0.1:8000/hypothesis/protocol?protocol=<PROTOCOL>' \
  -H 'accept: application/json'
```  
## Results

The results of the analysis are documented in the Results section of this repository. Key findings include:
- Significant differences in malicious likelihood between different protocols.
- The impact of connection duration on the likelihood of malicious activity.

## Future Work
Future enhancements could include:

- Integrating additional data sources for a more comprehensive analysis.
- Implementing real-time monitoring and prediction.
- Integrating a hardware/software list or network topology for better predictors.
- Using hardware/software information to predict initial access and possible lateral movement points within the network.
