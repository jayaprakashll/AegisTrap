
import requests
import time
from config import config

class VirusTotalAPI:
    def __init__(self, api_key=None):
        self.api_key = api_key if api_key else config['virustotal']['api_key']
        self.base_url = "https://www.virustotal.com/api/v3/files"

    def scan_file(self, file_path):
        try:
            with open(file_path, "rb") as file:
                headers = {"x-apikey": self.api_key}
                files = {"file": (file_path, file)}
                response = requests.post(self.base_url, headers=headers, files=files)
                response_json = response.json()
                return response_json.get("data", {}).get("id", None)
        except Exception as e:
            print(f"Error scanning file: {e}")
            return None

    def get_report(self, scan_id):
        url = f"{self.base_url}/{scan_id}"
        headers = {"x-apikey": self.api_key}
        try:
            while True:
                response = requests.get(url, headers=headers)
                response_json = response.json()
                if response_json.get("data", {}).get("attributes", {}).get("status") == "completed":
                    return response_json
                print("Waiting for analysis...")
                time.sleep(10)
        except Exception as e:
            print(f"Error retrieving report: {e}")
            return None

    def analyze_file(self, file_path):
        scan_id = self.scan_file(file_path)
        if scan_id:
            return self.get_report(scan_id)
        return None
