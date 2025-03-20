
import argparse
import os
import json
import yara
import requests
import tensorflow as tf
import numpy as np
import joblib
from datetime import datetime
from config import config
from utils.feature_extractor import extract_features
from utils.logger import log_detection
from utils.virustotal import scan_with_virustotal

def load_model():
    return tf.keras.models.load_model(config['ml_model']['model_path'])

def classify_file(model, file_path):
    features = extract_features(file_path)
    features = np.array(features).reshape(1, -1)
    prediction = model.predict(features)[0][0]
    return "malicious" if prediction >= config['ml_model']['confidence_threshold'] else "benign"

def scan_with_yara(file_path):
    matches = []
    for rule_file in os.listdir(config['yara']['rules_directory']):
        rule_path = os.path.join(config['yara']['rules_directory'], rule_file)
        rules = yara.compile(filepath=rule_path)
        match = rules.match(file_path)
        if match:
            matches.append(rule_file)
    return matches

def analyze(file_path):
    model = load_model()
    result = classify_file(model, file_path)
    yara_matches = scan_with_yara(file_path) if config['yara']['enable_yara'] else []
    vt_result = scan_with_virustotal(file_path) if config['virustotal']['enable'] else {}
    detection_data = {
        "file": os.path.basename(file_path),
        "prediction": result,
        "yara_matches": yara_matches,
        "virustotal": vt_result,
        "timestamp": datetime.now().isoformat()
    }
    log_detection(detection_data)
    print(json.dumps(detection_data, indent=4))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="Path to the file to analyze")
    args = parser.parse_args()
    if os.path.exists(args.file):
        analyze(args.file)
    else:
        print("Error: File not found")

if __name__ == "__main__":
    main()
