from email.mime import base
import logging
import json
import os
import math
import traceback
import azure.functions as func
import azure.durable_functions as df
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
from typing import List, Dict, Any
from datetime import datetime
from config.scan_context import ScanContext

app = func.Blueprint()

def split_targets_into_chunks(targets: List[str], chunk_size: int) -> List[List[str]]:
    """Split targets into chunks of specified size"""
    if not targets:
        return []
    
    chunks = []
    for i in range(0, len(targets), chunk_size):
        chunk = targets[i:i + chunk_size]
        chunks.append(chunk)
    
    return chunks

def read_txt_input(blob_path: str) -> List[str]:
    """Read .txt input file with one target per line"""
    connection_string = os.environ.get("AzureStorageConnectionString")
    if not connection_string:
        raise ValueError("AzureStorageConnectionString environment variable not set")
    
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    
    # Parse blob path: "scans/domain-scan_id/task/out/final_out.txt"
    path_parts = blob_path.split('/')
    if len(path_parts) < 4:
        raise ValueError(f"Invalid blob path format: {blob_path}")
    
    container_name = path_parts[0]
    blob_name = '/'.join(path_parts[1:])
    
    try:
        container_client = blob_service_client.get_container_client(container_name)
        blob_client = container_client.get_blob_client(blob_name)
        blob_content = blob_client.download_blob().readall()
        content_text = blob_content.decode('utf-8')
        
        # Parse one target per line
        targets = []
        for line in content_text.strip().split('\n'):
            line = line.strip()
            if line:  # Skip empty lines
                targets.append(line)
        
        logging.info(f"Read {len(targets)} targets from {blob_path}")
        return targets
                    
    except ResourceNotFoundError:
        raise ValueError(f"Blob not found: {blob_path}")
    except Exception as e:
        raise ValueError(f"Failed to read blob {blob_path}: {str(e)}")

def save_chunk_to_blob(chunk_data: List[str], scan_context: ScanContext, task_name: str, 
                       chunk_index: int, connection_string: str, type = None) -> str:
    """Save a chunk of targets to blob storage as .txt file"""
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    container_name = "scans"
    
    try:
        container_client = blob_service_client.get_container_client(container_name)
        container_client.get_container_properties()
    except ResourceNotFoundError:
        container_client = blob_service_client.create_container(container_name)
    
    # Save as simple .txt file with one target per line
    chunk_content = '\n'.join(chunk_data)
    blob_name = scan_context.get_chunk_path(task_name, chunk_index, type=type)
    blob_client = container_client.get_blob_client(blob_name)
    blob_client.upload_blob(chunk_content, overwrite=True)
    
    return f"{container_name}/{blob_name}"

@app.activity_trigger(input_name="config")
async def prepare_scan_messages(config: dict):
    logging.info("=== PREPARE SCAN MESSAGES ACTIVITY STARTED ===")
    try:
        scan_context = ScanContext.from_dict(config["scan_context"])
        task = config.get("task")
        input_blob_path = config.get("input_blob_path")
        split_threshold = config.get("split_threshold")
        
        logging.info(f"Config: enum_scan_id={scan_context.enum_scan_id}, vuln_scan_id={scan_context.vuln_scan_id}, task={task}, domain={scan_context.domain}")
        logging.info(f"Input blob path: {input_blob_path}, Split threshold: {split_threshold}")
        
        # Create base message with flattened scan_context
        base_message = {
            # Flatten scan_context keys into main object
            "scan_id": scan_context.vuln_scan_id if task == 'nuclei' else scan_context.enum_scan_id,
            "domain": scan_context.domain,
            "task": task,
            "type": config.get("type", None),
            "instance_id": config.get("instance_id"),
            "input_blob_path": input_blob_path,
            "output_format": config.get("output_format", "json"),
        }
        
        # If no input_blob_path, return single message with flattened config
        if not input_blob_path:
            logging.info("No input blob path provided, returning single message")
            return [base_message]
        
        # If no split_threshold, return single message with flattened config
        if not split_threshold:
            logging.info("No split threshold provided, returning single message")
            return [base_message]
        
        # Read .txt input file
        logging.info(f"Reading .txt input from blob: {input_blob_path}")
        targets = read_txt_input(input_blob_path)
        
        if not targets:
            logging.warning("No targets found in input blob, returning single message")
            return [base_message]
        
        # Check if splitting is needed
        if len(targets) <= split_threshold:
            logging.info(f"Target count ({len(targets)}) <= threshold ({split_threshold}), no splitting needed")
            return [base_message]
        
        # Split targets into chunks
        chunks = split_targets_into_chunks(targets, split_threshold)
        logging.info(f"Split {len(targets)} targets into {len(chunks)} chunks of size {split_threshold}")
        
        # Save chunks to blob storage and create messages
        connection_string = os.environ.get("AzureStorageConnectionString")
        if not connection_string:
            raise ValueError("AzureStorageConnectionString environment variable not set")
        
        messages = []
        for i, chunk in enumerate(chunks):
            # Save chunk to blob
            chunk_blob_path = save_chunk_to_blob(
                chunk, scan_context, task, i, connection_string, type=base_message["type"]
            )
            
            # Create message with modified config (flattened)
            message_config = base_message.copy()
            message_config["input_blob_path"] = chunk_blob_path
            message_config["chunk_index"] = i
            message_config["total_chunks"] = len(chunks)
            message_config["chunk_size"] = len(chunk)
            
            messages.append(message_config)
            logging.info(f"Created message {i+1}/{len(chunks)} with chunk blob: {chunk_blob_path}")
        
        logging.info(f"Prepared {len(messages)} messages with split input data")
        return messages
        
    except Exception as e:
        logging.error(f"prepare_scan_messages failed: {str(e)}")
        logging.error(traceback.format_exc())
        raise 