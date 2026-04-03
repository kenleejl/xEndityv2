#!/usr/bin/env python
"""
Docker container entry point script for running firmware analysis
"""
import os
import sys
import json
import logging
import subprocess
import time
from datetime import datetime
import argparse
from pathlib import Path
from pymongo import MongoClient
from bson import ObjectId

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("analysis-container")

def get_mongodb_client():
    """
    Get MongoDB client using connection details from environment variables
    """
    mongodb_host = os.environ.get('MONGODB_HOST', 'xendity-mongodb')  # Use container name as default
    mongodb_port = int(os.environ.get('MONGODB_PORT', '27017'))
    
    # Build connection string - no authentication is used in the application
    connection_string = f"mongodb://{mongodb_host}:{mongodb_port}/"
    logger.info(f"Using connection string template: mongodb://host:port/")
    
    # Connect to MongoDB with retry logic
    max_retries = 3
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            logger.info(f"Connecting to MongoDB at {mongodb_host}:{mongodb_port} (attempt {attempt+1}/{max_retries})")
            
            # Use a shorter timeout for the connection test
            client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
            
            # Test the connection by accessing the server info
            client.server_info()
            logger.info("Successfully connected to MongoDB")
            return client
            
        except Exception as e:
            logger.error(f"MongoDB connection error (attempt {attempt+1}/{max_retries}): {str(e)}")
            
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                logger.error(f"Failed to connect to MongoDB after {max_retries} attempts")
                raise

def update_analysis_status(client, analysis_id, status, progress):
    """
    Update analysis status in MongoDB
    """
    # Use the same database name as in db_utils.py
    db = client[os.environ.get('MONGODB_DB', 'xendity_firmwares')]
    collection = db['firmware_analysis']
    
    logger.info(f"Updating analysis {analysis_id} status: {status}, progress: {progress}")
    
    try:
        result = collection.update_one(
            {'_id': ObjectId(analysis_id)},
            {'$set': {'status': status, 'progress': progress}}
        )
        if result.modified_count > 0:
            return True
        else:
            logger.warning(f"No document updated for ID {analysis_id}")
            return False
    except Exception as e:
        logger.error(f"Error updating analysis status: {str(e)}")
        return False

def save_analysis_results(client, analysis_id, results):
    """
    Save analysis results to MongoDB
    """
    # Use the same database name as in db_utils.py
    db = client[os.environ.get('MONGODB_DB', 'xendity_firmwares')]
    collection = db['firmware_analysis']
    
    logger.info(f"Saving analysis results for {analysis_id}")
    
    try:
        # Prepare update data
        update_data = {
            'status': 'completed',
            'progress': 100,
            'file_format': results.get('file_format', {}),
            'hashes': results.get('hashes', {}),
            'entropy': results.get('entropy', {}),
            'encryption': results.get('encryption', {}),
            'strings_analysis': results.get('strings_analysis', {}),
            'extraction_points': results.get('extraction_points', {}),
            'metadata': results.get('metadata', {}),
            'visualization': results.get('visualization', {})
        }
        
        # Extract strategy information if present
        if 'extraction_strategy' in results:
            update_data['extraction_strategy'] = results['extraction_strategy']
        
        # Update document
        result = collection.update_one(
            {'_id': ObjectId(analysis_id)},
            {'$set': update_data}
        )
        
        if result.modified_count > 0:
            logger.info(f"Successfully saved results for analysis {analysis_id}")
            return True
        else:
            logger.warning(f"No document updated for ID {analysis_id}")
            return False
    except Exception as e:
        logger.error(f"Error saving analysis results: {str(e)}")
        return False

def extract_strategy_from_output(output_lines):
    """
    Extract strategy information from analysis output
    """
    strategy = {
        'recommended_extractors': [],
        'format_flags': {},
        'special_handling': [],
        'confidence': 'unknown'
    }
    
    # Extract strategy information from output lines
    in_strategy_section = False
    for line in output_lines:
        if "EXTRACTION STRATEGY:" in line:
            in_strategy_section = True
            continue
        
        if in_strategy_section:
            if "Recommended extractors:" in line:
                extractors = line.split("Recommended extractors:")[1].strip()
                strategy['recommended_extractors'] = [e.strip() for e in extractors.split(",")]
            elif "Confidence:" in line:
                strategy['confidence'] = line.split("Confidence:")[1].strip()
            elif "FORMAT FLAGS:" in line:
                # Next lines will contain format flags
                continue
            elif line.strip().startswith("SPECIAL HANDLING:"):
                # Next lines will contain special handling
                continue
            elif line.strip().startswith("-"):
                # Special handling item
                handling = line.strip()[2:].strip()
                strategy['special_handling'].append(handling)
            elif "=" in line and not line.startswith("["):
                # Format flag
                parts = line.strip().split("=")
                if len(parts) == 2:
                    flag = parts[0].strip()
                    value = parts[1].strip()
                    try:
                        strategy['format_flags'][flag] = int(value)
                    except ValueError:
                        strategy['format_flags'][flag] = value
            elif "No specialized format detected" in line:
                strategy['format_flags']["DEFAULT_EXTRACTION"] = 1
            elif "Specialized format detected" in line:
                # Already captured in format flags
                pass
            elif line.startswith("[") or line.strip() == "":
                # End of strategy section or empty line
                in_strategy_section = False
    
    return strategy

def run_analysis(analysis_id, firmware_path):
    """
    Run the analysis process on a firmware file
    """
    logger.info(f"Starting analysis {analysis_id} for firmware {firmware_path}")
    
    try:
        # Connect to MongoDB
        try:
            mongo_client = get_mongodb_client()
        except Exception as e:
            logger.error(f"Fatal error connecting to MongoDB: {str(e)}")
            logger.error("Cannot proceed with analysis without database connection")
            # Still run the analysis, but we can't update status
            mongo_client = None
        
        # Update status to running (if MongoDB is available)
        if mongo_client:
            update_analysis_status(mongo_client, analysis_id, "running", 5)
        
        # Get the fw_binary_analysis script path
        script_path = os.path.join('/app', 'fw_binary_analysis', 'fw_binary_analysis.py')
        
        # Use the specified output directory (should be within the mounted firmware directory)
        output_dir = os.environ.get('OUTPUT_DIR')
        if not output_dir:
            # Fallback: create analysis directory next to firmware file
            firmware_name = os.path.splitext(os.path.basename(firmware_path))[0]
            firmware_dir = os.path.dirname(firmware_path)
            output_dir = os.path.join(firmware_dir, f"{firmware_name}_analysis")
            logger.warning(f"No OUTPUT_DIR environment variable set, using default: {output_dir}")
        
        # Create the output directory
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Using output directory: {output_dir}")
        logger.info(f"Analysis results will be saved to: {output_dir}")
        
        # Define output JSON path
        output_json = os.path.join(output_dir, "analysis_results.json")
        
        # Update status (if MongoDB is available)
        if mongo_client:
            update_analysis_status(mongo_client, analysis_id, "running", 10)
        
        # Run fw_binary_analysis with subprocess
        cmd = [
            sys.executable,
            script_path,
            firmware_path,
            "-o", output_json,
            "-s"  # Generate strategy
        ]
        
        logger.info(f"Running command: {' '.join(cmd)}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Process output to track progress
        if mongo_client:
            update_analysis_status(mongo_client, analysis_id, "analyzing_file_format", 15)
        output_lines = []
        
        for line in iter(process.stdout.readline, ''):
            output_lines.append(line.rstrip())
            logger.info(f"Analysis output: {line.rstrip()}")
            
            # Update progress based on output (if MongoDB is available)
            if mongo_client:
                if "Checking file format" in line:
                    update_analysis_status(mongo_client, analysis_id, "checking_file_format", 20)
                elif "Calculating hashes" in line:
                    update_analysis_status(mongo_client, analysis_id, "calculating_hashes", 30)
                elif "Analyzing entropy" in line:
                    update_analysis_status(mongo_client, analysis_id, "analyzing_entropy", 40)
                elif "Detecting encryption" in line:
                    update_analysis_status(mongo_client, analysis_id, "detecting_encryption", 50)
                elif "Analyzing strings" in line:
                    update_analysis_status(mongo_client, analysis_id, "analyzing_strings", 60)
                elif "Finding extraction points" in line:
                    update_analysis_status(mongo_client, analysis_id, "finding_extraction_points", 70)
                elif "Analyzing metadata" in line:
                    update_analysis_status(mongo_client, analysis_id, "analyzing_metadata", 80)
                elif "Generating byte pattern" in line:
                    update_analysis_status(mongo_client, analysis_id, "generating_visualization", 90)
                elif "Analysis completed" in line:
                    update_analysis_status(mongo_client, analysis_id, "completed", 95)
        
        # Wait for process to complete
        process.wait()
        
        # Check for errors
        if process.returncode != 0:
            error_output = process.stderr.read()
            logger.error(f"Analysis process failed: {error_output}")
            if mongo_client:
                update_analysis_status(mongo_client, analysis_id, "failed", 0)
            return
        
        # Load results from JSON file
        if os.path.exists(output_json):
            with open(output_json, 'r') as f:
                analysis_results = json.load(f)
            
            # Extract strategy information
            extraction_strategy = extract_strategy_from_output(output_lines)
            analysis_results['extraction_strategy'] = extraction_strategy
            
            # Save results to MongoDB (if available)
            if mongo_client:
                save_analysis_results(mongo_client, analysis_id, analysis_results)
                logger.info(f"Analysis {analysis_id} completed and saved successfully")
            else:
                logger.warning("Analysis completed but couldn't save to MongoDB (no connection)")
                # Save results to a local file as backup
                backup_file = f"/tmp/analysis_{analysis_id}_results.json"
                with open(backup_file, 'w') as f:
                    json.dump(analysis_results, f)
                logger.info(f"Analysis results saved to backup file: {backup_file}")
        else:
            logger.error(f"Analysis output file not found: {output_json}")
            if mongo_client:
                update_analysis_status(mongo_client, analysis_id, "failed", 0)
    
    except Exception as e:
        logger.error(f"Error running analysis process: {str(e)}")
        try:
            if mongo_client:
                update_analysis_status(mongo_client, analysis_id, "failed", 0)
        except:
            logger.error("Could not update analysis status to failed")

def main():
    """
    Main entry point for the container
    """
    parser = argparse.ArgumentParser(description='Run firmware analysis in Docker container')
    parser.add_argument('--analysis-id', required=True, help='MongoDB analysis document ID')
    parser.add_argument('--firmware-path', required=True, help='Path to firmware file within container')
    
    args = parser.parse_args()
    
    # Run the analysis
    run_analysis(args.analysis_id, args.firmware_path)

if __name__ == "__main__":
    main() 