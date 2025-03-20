import argparse
import os
import json
import time
import hashlib
from feature_extraction import extract_features
from ml_model import classify_file
from yara_scanner import scan_with_yara
from virustotal_api import check_virustotal
from logger import setup_logger
from report_generate import generate_report

logger = setup_logger()


# ADD THE FILE PATH OF THE CONFIF AND YARA RULES FOR PROPERSCANNER

def compute_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
    except Exception as e:
        logger.error(f"Error computing hash: {e}")
    return None

def analyze_file(file_path):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        logger.info(f"Analyzing file: {file_path}")
        
        file_hash = compute_hash(file_path)
        if file_hash is None:
            return
        
        logger.info(f"File SHA256: {file_hash}")
        
        start_time = time.time()
        
        features = extract_features(file_path)
        if not features:
            raise ValueError("Feature extraction failed.")
        
        ml_prediction = classify_file(features)
        yara_results = scan_with_yara(file_path)
        vt_results = check_virustotal(file_path)
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        analysis_results = {
            "file": file_path,
            "sha256": file_hash,
            "ml_prediction": ml_prediction,
            "yara_matches": yara_results,
            "virustotal": vt_results,
            "execution_time": execution_time
        }
        
        report_path = generate_report(analysis_results)
        logger.info(f"Analysis complete. Report saved at {report_path}")
    except FileNotFoundError as e:
        logger.error(e)
    except ValueError as e:
        logger.warning(e)
    except Exception as e:
        logger.exception(f"Unexpected error during file analysis: {e}")

def batch_analyze(directory):
    try:
        if not os.path.isdir(directory):
            raise NotADirectoryError(f"Invalid directory: {directory}")
        
        files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        
        if not files:
            logger.warning("No files found in the directory.")
            return
        
        logger.info(f"Starting batch analysis for {len(files)} files.")
        
        for file in files:
            analyze_file(file)
        
        logger.info("Batch analysis completed.")
    except NotADirectoryError as e:
        logger.error(e)
    except Exception as e:
        logger.exception(f"Unexpected error during batch analysis: {e}")

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="AegisTrap Malware Analysis Tool")
        parser.add_argument("--file", help="Path to the file to analyze")
        parser.add_argument("--dir", help="Path to the directory for batch analysis")
        args = parser.parse_args()
        
        if args.file:
            analyze_file(args.file)
        elif args.dir:
            batch_analyze(args.dir)
        else:
            raise ValueError("Please specify either --file or --dir argument.")
    except ValueError as e:
        logger.error(e)
    except Exception as e:
        logger.exception(f"Unexpected error in main execution: {e}")

