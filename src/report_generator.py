import json
import os
from datetime import datetime
from config import config

def generate_report(detection_results, output_dir=None, metadata=None):
    if output_dir is None:
        output_dir = config['reporting']['report_directory']
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    report_file = os.path.join(output_dir, f"report_{timestamp}.json")
    
    report_data = {
        "timestamp": timestamp,
        "results": detection_results,
        "metadata": metadata if metadata else {}
    }
    
    try:
        with open(report_file, "w") as f:
            json.dump(report_data, f, indent=4)
        return report_file
    except Exception as e:
        print(f"Error generating report: {e}")
        return None

def read_report(report_file):
    try:
        with open(report_file, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error reading report: {e}")
        return None

def delete_old_reports(output_dir=None, retention_days=30):
    if output_dir is None:
        output_dir = config['reporting']['report_directory']
    
    now = datetime.now()
    try:
        for filename in os.listdir(output_dir):
            file_path = os.path.join(output_dir, filename)
            if os.path.isfile(file_path):
                file_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                if (now - file_time).days > retention_days:
                    os.remove(file_path)
    except Exception as e:
        print(f"Error deleting old reports: {e}")
