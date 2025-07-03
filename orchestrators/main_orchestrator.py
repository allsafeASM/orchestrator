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
        enum_scan_id = input_data.get("enum_scan_id")
        vuln_scan_id = input_data.get("vuln_scan_id", None)
        user_id = input_data.get("user_id")  # Add user_id requirement
        task_sequence = input_data.get("task_sequence") # Can be None if not provided
        
        # Validate required fields
        if not user_id:
            error_msg = "user_id is required"
            logging.error(error_msg)
            return {"success": False, "error": error_msg}
        
        logging.info(f"=== MAIN ORCHESTRATOR STARTED ===")
        logging.info(f"Scan IDs: [{enum_scan_id}, {vuln_scan_id}], Domain: {domain}, User ID: {user_id}, Tasks: {task_sequence or 'default'}")
        
        # Create the scan context object to hold state
        scan_context = ScanContext(
            enum_scan_id=enum_scan_id,
            vuln_scan_id=vuln_scan_id,
            domain=domain,
            domain_id=input_data.get("domain_id"),
            user_id=user_id  # Add user_id to scan context
        )
        
        scan_context_dict = scan_context.to_dict()
     
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
        
        # 2. Execute enumeration scan (subfinder, dns_resolve, port_scan, httpx)
        logging.info("Starting enumeration scan...")
        enum_scan_input = {
            "scan_context": scan_context_dict,
        }

        enum_scan_result = yield context.call_sub_orchestrator(
            "enumeration_scan_orchestrator",
            enum_scan_input
        )
        
        if not enum_scan_result or enum_scan_result.get("status") != "completed":
            error_msg = f"Enumeration scan failed or did not complete. Result: {enum_scan_result}"
            logging.error(error_msg)
            return {"success": False, "error": error_msg}

        # 3. Execute vulnerability scan (nuclei) if vuln_scan_id is provided
        vuln_scan_result = None
        if vuln_scan_id:
            logging.info("Starting vulnerability scan...")
            vuln_scan_input = {
                "scan_context": scan_context_dict,
            }

            vuln_scan_result = yield context.call_sub_orchestrator(
                "vulnerability_scan_orchestrator",
                vuln_scan_input
            )
            
            if not vuln_scan_result or vuln_scan_result.get("status") != "completed":
                error_msg = f"Vulnerability scan failed or did not complete. Result: {vuln_scan_result}"
                logging.error(error_msg)
                return {"success": False, "error": error_msg}

        logging.info(f"=== MAIN ORCHESTRATOR COMPLETED SUCCESSFULLY ===")
        
        return {
            "success": True,
            "enum_scan_id": enum_scan_id,
            "vuln_scan_id": vuln_scan_id,
            "domain": domain,
            "user_id": user_id,
            "results": {
                "enumeration_scan": enum_scan_result,
                "vulnerability_scan": vuln_scan_result
            }
        }
        
    except Exception as e:
        error_msg = f"Main orchestrator failed with exception: {str(e)}"
        logging.error(error_msg)
        logging.error(f"Exception details: {traceback.format_exc()}")
        return {"success": False, "error": error_msg}
