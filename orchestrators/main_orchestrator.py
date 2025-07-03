import logging
import json
import traceback
import azure.durable_functions as df
import azure.functions as func
from config.scan_context import ScanContext

app = func.Blueprint()

@app.function_name("main_orchestrator")
@app.orchestration_trigger(context_name="context")
def main_orchestrator(context: df.DurableOrchestrationContext):
    """Main orchestrator for security scanning workflow"""
    try:
        # Get input data from the HTTP trigger
        input_data = context.get_input()
        domain = input_data.get("domain")
        scan_id = input_data.get("enum_scan_id")
        user_id = input_data.get("user_id")  # Add user_id requirement
        task_sequence = input_data.get("task_sequence") # Can be None if not provided
        
        # Validate required fields
        if not user_id:
            error_msg = "user_id is required"
            logging.error(error_msg)
            return {"success": False, "error": error_msg}
        
        logging.info(f"=== MAIN ORCHESTRATOR STARTED ===")
        logging.info(f"Scan ID: {scan_id}, Domain: {domain}, User ID: {user_id}, Tasks: {task_sequence or 'default'}")
        
        # Create the scan context object to hold state
        scan_context = ScanContext(
            scan_id=scan_id,
            domain=domain,
            domain_id=input_data.get("domain_id"),
            user_id=user_id  # Add user_id to scan context
        )
        
        scan_context_dict = scan_context.to_dict()
        
        # --- START DEBUGGING STEP ---
        # The purpose of this block is to find the exact value causing the serialization error.
        try:
            # Attempt to serialize the dictionary. If it contains a coroutine, this line will fail.
            json.dumps(scan_context_dict)
            logging.info("Serialization check passed for scan_context_dict.")
        except TypeError as e:
            # This catches the "Object of type coroutine is not JSON serializable" error.
            logging.error("--- SERIALIZATION FAILED ---")
            logging.error(f"ERROR: {e}")
            logging.error("The dictionary created from ScanContext contains a non-serializable value (likely a coroutine).")
            # This log will show you the exact dictionary and its values so you can find the problem.
            logging.error(f"Problematic Dictionary Contents: {scan_context_dict}")
            # Fail the orchestration immediately to prevent further issues.
            raise Exception("Failed to serialize ScanContext. Check logs for details.")
        # --- END DEBUGGING STEP ---
        
        # 1. Validate domain exists in database and belongs to user
        domain_validation_result = yield context.call_activity(
            "validate_domain", 
            {"scan_context": scan_context_dict}
        )
        
        if not domain_validation_result.get("valid"):
            error_msg = f"Domain validation failed: {domain_validation_result.get('error')}"
            logging.error(error_msg)
            
            return {"success": False, "error": error_msg}
        
        # Update scan context object AND the dictionary with the validated domain_id
        scan_context.domain_id = domain_validation_result.get("domain_id")
        scan_context_dict["domain_id"] = scan_context.domain_id
        
        # 2. Execute the main task pipeline
        task_pipeline_input = {
            "scan_context": scan_context_dict,
        }
        if task_sequence:
            task_pipeline_input["task_sequence"] = task_sequence

        task_pipeline_result = yield context.call_sub_orchestrator(
            "task_pipeline_orchestrator",
            task_pipeline_input
        )
        
        if not task_pipeline_result or task_pipeline_result.get("status") != "completed":
            error_msg = f"Task pipeline failed or did not complete. Result: {task_pipeline_result}"
            logging.error(error_msg)
            return {"success": False, "error": error_msg}

        logging.info(f"=== MAIN ORCHESTRATOR COMPLETED SUCCESSFULLY ===")
        
        return {
            "success": True,
            "scan_id": scan_id,
            "domain": domain,
            "user_id": user_id,
            "results": {
                "task_pipeline": task_pipeline_result
            }
        }
        
    except Exception as e:
        error_msg = f"Main orchestrator failed with exception: {str(e)}"
        logging.error(error_msg)
        logging.error(f"Exception details: {traceback.format_exc()}")
        return {"success": False, "error": error_msg}
