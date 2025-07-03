"""
Enumeration Scan Orchestrator
Handles sequential execution of enumeration tasks: subfinder, dns_resolve, port_scan, httpx
"""
import logging
import traceback
import azure.durable_functions as df
import azure.functions as func
from config.task_registry import get_task_sequence
from config.scan_context import ScanContext

app = func.Blueprint()

@app.orchestration_trigger(context_name="context")
def enumeration_scan_orchestrator(context: df.DurableOrchestrationContext):
    logging.info("=== ENUMERATION SCAN ORCHESTRATOR STARTED ===")
    try:
        initial_input = context.get_input()
        scan_context = ScanContext.from_dict(initial_input["scan_context"])
        parent_instance_id = context.instance_id
        
        # Define enumeration task sequence
        enum_task_sequence = ["subfinder", "dns_resolve", "port_scan", "httpx"]
        
        logging.info(f"Enumeration scan config: enum_scan_id={scan_context.enum_scan_id}, domain={scan_context.domain}, tasks={enum_task_sequence}")
        
        # Get configurations for enumeration tasks
        task_configs = get_task_sequence(enum_task_sequence)
        if not task_configs:
            raise ValueError(f"No valid task configurations found for enumeration sequence: {enum_task_sequence}")
        
        results = []
        
        # Execute enumeration tasks sequentially
        for i, task_config in enumerate(task_configs):
            task_name = task_config.task_name
            status_description = task_config.description
            logging.info(f"Starting enumeration task {i+1}/{len(task_configs)}: {task_name}")
            
            # Update enumeration scan status before running the task
            yield context.call_activity(
                "update_enumeration_scan_status",
                {
                    "enumeration_scan_id": scan_context.enum_scan_id,
                    "status": status_description
                }
            )
            
            # Create task-specific configuration
            task_execution_config = {
                "scan_context": scan_context.to_dict(),
                "instance_id": f"{parent_instance_id}-{scan_context.enum_scan_id}-{task_name}",
                "task": task_name,
                "task_index": i,
                "total_tasks": len(task_configs)
            }
            
            # Use prepared input from previous task - but only if it's not the first task
            if i > 0:  # Only set input_blob_path for tasks after the first one
                task_execution_config["input_blob_path"] = f"scans/{scan_context.domain}-{scan_context.enum_scan_id}/{task_name}/in/input.txt"
                logging.info(f"Task {task_name} will use prepared input: {task_execution_config['input_blob_path']}")
            else:
                logging.info(f"Task {task_name} is the first task, no input required")
            
            # Add task-specific parameters
            task_dict = task_config.to_dict()
            for key, value in task_dict.items():
                if key not in ["task_name", "description", "input_blob_path"]:  # Skip metadata fields
                    task_execution_config[key] = value
            
            # Execute the task
            task_result = yield context.call_sub_orchestrator(
                "tool_stage_orchestrator",
                task_execution_config,
                instance_id=task_execution_config["instance_id"]
            )
            
            results.append({
                "task": task_name,
                "result_path": task_result.get("aggregated_result"),
                "status": "completed"
            })
            
            logging.info(f"Completed enumeration task {task_name}, result: {task_result.get('aggregated_result')}")

        # After all enumeration tasks are done, store the final enumeration scan results
        httpx_blob_path = f"scans/{scan_context.domain}-{scan_context.enum_scan_id}/httpx/out/final_out.json"
        dns_resolve_blob_path = f"scans/{scan_context.domain}-{scan_context.enum_scan_id}/dns_resolve/out/final_out.json"

        yield context.call_activity(
            "save_enumeration_scan_results",
            {
                "scan_context": scan_context.to_dict(),
                "httpx_blob_path": httpx_blob_path,
                "dns_resolve_blob_path": dns_resolve_blob_path
            }
        )

        # Create final enumeration scan summary
        enum_scan_summary = {
            "enum_scan_id": scan_context.enum_scan_id,
            "domain": scan_context.domain,
            "status": "completed",
            "total_tasks": len(task_configs),
            "completed_tasks": len(results),
            "task_results": results
        }
        
        logging.info(f"=== ENUMERATION SCAN ORCHESTRATOR COMPLETED === {enum_scan_summary}")

        # Update final enumeration scan status
        yield context.call_activity(
            "update_enumeration_scan_status",
            {"enumeration_scan_id": scan_context.enum_scan_id, "status": "Completed"}
        )

        return enum_scan_summary
        
    except Exception as e:
        logging.error(f"Enumeration scan orchestrator failed: {str(e)}")
        logging.error(traceback.format_exc())
        raise 