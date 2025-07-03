import logging
import traceback
import azure.functions as func
import azure.durable_functions as df
from config.scan_context import ScanContext
import os
import json
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
from typing import List, Dict
from datetime import datetime
import asyncio

app = func.Blueprint()


@app.activity_trigger(input_name="payload")
async def save_to_database(payload: dict):
    logging.info("=== SAVE TO DATABASE ACTIVITY STARTED ===")
    try:
        scan_context = ScanContext.from_dict(payload["scan_context"])
        task = payload.get("task")
        output_blob_path = payload.get("output_blob_path")
        
        logging.info(f"Processing task: {task}")
        logging.info(f"Output blob path: {output_blob_path}")
        
 
        
        if not output_blob_path:
            logging.warning("No output blob path provided, skipping database save")
            
            return {"success": False, "error": "No output blob path provided"}
        
        # Read output from blob storage
        output_data = read_task_output(output_blob_path, task)
        
        if not output_data:
            logging.warning("No output data found, skipping database save")
            
            return {"success": False, "error": "No output data found"}
        
        # Run async database operations
        await save_task_results(scan_context, task, output_data)
        
        logging.info(f"Successfully saved {task} results to database")
        
        # Log successful completion
        return {"success": True, "task": task, "data_saved": True}
        
    except Exception as e:
        logging.error(f"Failed to save to database: {str(e)}")
        logging.error(traceback.format_exc())
        
        # Log error
        return {"success": False, "error": str(e)}

async def save_task_results(scan_context: ScanContext, task: str, output_data: any):
    """Save task results to database using async operations"""
    from database.db_manager import DatabaseManager
    
    try:
        # Create a new database manager instance
        db_manager = DatabaseManager()
        
        if task == "subfinder":
            await save_subfinder_results(scan_context, output_data, db_manager)
        elif task == "dns_resolve":
            await save_dns_resolve_results(scan_context, output_data, db_manager)
        elif task == "port_scan":
            await save_port_scan_results(scan_context, output_data, db_manager)
        else:
            logging.warning(f"Database save not implemented for task: {task}")
    except Exception as e:
        logging.error(f"Failed to save {task} results: {str(e)}")
        raise

def read_task_output(blob_path: str, task: str) -> any:
    """Read task output from blob storage"""
    connection_string = os.environ.get("AzureStorageConnectionString")
    if not connection_string:
        raise ValueError("AzureStorageConnectionString environment variable not set")
    
    blob_service_client = BlobServiceClient.from_connection_string(connection_string)
    
    # Parse blob path: "scans/domain-scan_id/task/out/final_out.{extension}"
    path_parts = blob_path.split('/')
    logging.info(f"Parsing blob path: '{blob_path}' into {len(path_parts)} parts: {path_parts}")
    
    if len(path_parts) < 4:
        raise ValueError(f"Invalid blob path format: {blob_path}")
    
    container_name = path_parts[0]
    blob_name = '/'.join(path_parts[1:])
    
    logging.info(f"Container: '{container_name}', Blob name: '{blob_name}'")
    
    try:
        container_client = blob_service_client.get_container_client(container_name)
        blob_client = container_client.get_blob_client(blob_name)
        blob_content = blob_client.download_blob().readall()
        content_text = blob_content.decode('utf-8')
        
        if task == "subfinder" and blob_name.endswith('.txt'):
            # Handle subfinder text output (one subdomain per line)
            subdomains = []
            for line in content_text.strip().split('\n'):
                line = line.strip()
                if line:  # Skip empty lines
                    subdomains.append(line)
            return subdomains
            
        elif blob_name.endswith('.json'):
            # Handle JSON output
            result_data = json.loads(content_text)
            if "data" in result_data and "output" in result_data["data"]:
                return result_data["data"]["output"]
            else:
                return result_data
        else:
            raise ValueError(f"Unsupported file format for task {task}: {blob_path}")
                    
    except ResourceNotFoundError:
        raise ValueError(f"Blob not found: {blob_path}")
    except Exception as e:
        raise ValueError(f"Failed to read blob {blob_path}: {str(e)}")

async def save_subfinder_results(scan_context: ScanContext, subdomains: List[str], db_manager):
    """Save subfinder results to database"""
    try:
        # Use the correct async method from DatabaseManager
        result = await db_manager.store_subdomains_from_subfinder(
            domain_id=scan_context.domain_id,
            subdomain_names=subdomains
        )
        
        if result.get("success"):
            logging.info(f"Saved subfinder results: {result.get('created_count', 0)} new, {result.get('updated_count', 0)} updated subdomains")
        else:
            logging.error(f"Failed to save subfinder results: {result.get('error', 'Unknown error')}")
            raise Exception(f"Database operation failed: {result.get('error')}")
            
    except Exception as e:
        logging.error(f"Failed to save subfinder results: {str(e)}")
        raise

async def save_dns_resolve_results(scan_context: ScanContext, dns_records: Dict[str, Dict], db_manager):
    """Save DNS resolution results to database"""
    try:
        # Use the correct async method from DatabaseManager
        result = await db_manager.store_dns_resolve_results_batch(
            domain_id=scan_context.domain_id,
            dns_results=dns_records
        )
        
        if result.get("success"):
            logging.info(f"Saved DNS resolve results: {result.get('total_created_ips', 0)} IPs, {result.get('total_created_relationships', 0)} relationships, {result.get('total_created_cnames', 0)} CNAMEs")
        else:
            logging.error(f"Failed to save DNS resolve results: {result.get('error', 'Unknown error')}")
            raise Exception(f"Database operation failed: {result.get('error')}")
            
    except Exception as e:
        logging.error(f"Failed to save DNS resolve results: {str(e)}")
        raise

async def save_port_scan_results(scan_context: ScanContext, port_scan_data: Dict[str, List[Dict]], db_manager):
    """Save port scan results to database"""
    try:
        # Use the correct async method from DatabaseManager
        result = await db_manager.store_port_scan_results_batch(
            domain_id=scan_context.domain_id,
            port_scan_results=port_scan_data
        )
        
        if result.get("success"):
            logging.info(f"Saved port scan results: {result.get('created_ports', 0)} new ports across {result.get('updated_ips', 0)} IPs")
        else:
            logging.error(f"Failed to save port scan results: {result.get('error', 'Unknown error')}")
            raise Exception(f"Database operation failed: {result.get('error')}")
            
    except Exception as e:
        logging.error(f"Failed to save port scan results: {str(e)}")
        raise
