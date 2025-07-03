import logging
import traceback
import azure.functions as func
from database.db_manager import DatabaseManager

app = func.Blueprint()

@app.activity_trigger(input_name="payload")
async def update_enumeration_scan_status(payload: dict):
    try:
        enumeration_scan_id = payload["enumeration_scan_id"]
        status = payload["status"]
        logging.info(f"Updating enumeration_scan_id={enumeration_scan_id} to status='{status}'")
        db_manager = DatabaseManager()
        result = await db_manager.update_enumeration_scan_status(enumeration_scan_id, status)
        if result.get("success"):
            logging.info(f"Successfully updated enumeration_scan_id={enumeration_scan_id} to status='{status}'")
        else:
            logging.error(f"Failed to update enumeration_scan_id={enumeration_scan_id}: {result.get('error')}")
        return result
    except Exception as e:
        logging.error(f"Exception while updating enumeration_scan_id={enumeration_scan_id} to status='{status}': {str(e)}")
        logging.error(traceback.format_exc())
        return {"success": False, "error": str(e)} 