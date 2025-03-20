
import yara
import os
import logging
from config import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class YaraScanner:
    def __init__(self, rules_directory=None):
        self.rules_directory = rules_directory if rules_directory else config['yara']['rules_directory']
        self.rules = self.load_rules()

    def load_rules(self):
        try:
            rule_files = [os.path.join(self.rules_directory, f) for f in os.listdir(self.rules_directory) if f.endswith('.yar') or f.endswith('.yara')]
            rules_dict = {f"rule_{i}": path for i, path in enumerate(rule_files)}
            compiled_rules = yara.compile(filepaths=rules_dict) if rules_dict else None
            logging.info("YARA rules successfully loaded.")
            return compiled_rules
        except Exception as e:
            logging.error(f"Error loading YARA rules: {e}")
            return None

    def scan_file(self, file_path):
        if not self.rules:
            logging.warning("No YARA rules loaded.")
            return None
        try:
            matches = self.rules.match(file_path)
            if matches:
                logging.info(f"Threat detected in {file_path}: {matches}")
                return matches
            else:
                logging.info(f"No threats detected in {file_path}.")
                return "No threats detected."
        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return None

    def scan_directory(self, directory_path):
        results = {}
        if not os.path.exists(directory_path):
            logging.error("Directory does not exist.")
            return None
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                results[file_path] = self.scan_file(file_path)
        logging.info("Directory scan completed.")
        return results

    def scan_multiple_files(self, file_paths):
        results = {}
        for file_path in file_paths:
            results[file_path] = self.scan_file(file_path)
        return results
