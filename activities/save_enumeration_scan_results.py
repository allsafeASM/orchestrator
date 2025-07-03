import logging
import traceback
import azure.functions as func
import os
import json
from azure.storage.blob import BlobServiceClient
from database.db_manager import DatabaseManager

app = func.Blueprint()

@app.activity_trigger(input_name="payload")
async def save_enumeration_scan_results(payload: dict):
    try:
        scan_context = payload["scan_context"]
        httpx_blob_path = payload["httpx_blob_path"]
        dns_blob_path = payload["dns_resolve_blob_path"]

        # Read blobs
        connection_string = os.environ.get("AzureStorageConnectionString")
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)

        def read_blob(blob_path):
            path_parts = blob_path.split('/')
            container_name = path_parts[0]
            blob_name = '/'.join(path_parts[1:])
            blob_client = blob_service_client.get_container_client(container_name).get_blob_client(blob_name)
            return blob_client.download_blob().readall().decode('utf-8')

        httpx_data = json.loads(read_blob(httpx_blob_path))
        dns_data = json.loads(read_blob(dns_blob_path))

        # Extract outputs
        httpx_output = httpx_data["data"]["output"]
        dns_output = dns_data["data"]["output"]

        db_manager = DatabaseManager()
        result = await db_manager.store_enumeration_scan_results(
            enumeration_scan_id=scan_context["enum_scan_id"],
            httpx_output=httpx_output,
            dns_resolve_output=dns_output
        )

        # Update total_assets and scan_time_elapsed
        if result.get("success"):
            total_assets = result.get("inserted", 0)
            summary_update = await db_manager.update_enumeration_scan_summary(
                enumeration_scan_id=scan_context["enum_scan_id"],
                total_assets=total_assets
            )
            if summary_update.get("success"):
                logging.info(f"Updated enumeration scan summary for id={scan_context['enum_scan_id']}: total_assets={total_assets}")
            else:
                logging.error(f"Failed to update enumeration scan summary: {summary_update.get('error')}")
        return result
    except Exception as e:
        logging.error(f"Failed to save enumeration scan results: {str(e)}")
        logging.error(traceback.format_exc())
        return {"success": False, "error": str(e)} 