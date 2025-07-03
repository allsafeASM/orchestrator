"""
Task Pipeline Orchestrator
Handles sequential execution of security scanning tasks
"""
import logging
import traceback
import azure.durable_functions as df
import azure.functions as func
from config.task_registry import get_task_sequence, get_default_scan_sequence
from config.scan_context import ScanContext

app = func.Blueprint()

@app.orchestration_trigger(context_name="context")
def task_pipeline_orchestrator(context: df.DurableOrchestrationContext):
    logging.info("=== TASK PIPELINE ORCHESTRATOR STARTED ===")
    try:
        initial_input = context.get_input()
        scan_context = ScanContext.from_dict(initial_input["scan_context"])
        parent_instance_id = context.instance_id
        
        # Get task sequence - either from input or use default
        task_sequence = get_default_scan_sequence()
        
        logging.info(f"Pipeline config: scan_id={scan_context.scan_id}, domain={scan_context.domain}, tasks={task_sequence}")
        
        # Get configurations for all tasks
        task_configs = get_task_sequence(task_sequence)
        if not task_configs:
            raise ValueError(f"No valid task configurations found for sequence: {task_sequence}")
        
        results = []
        
        # Execute tasks sequentially
        for i, task_config in enumerate(task_configs):
            task_name = task_config.task_name
            status_description = task_config.description
            logging.info(f"Starting task {i+1}/{len(task_configs)}: {task_name}")
            
            # Update status before running the task
            yield context.call_activity(
                "update_enumeration_scan_status",
                {
                    "enumeration_scan_id": scan_context.scan_id,
                    "status": status_description
                }
            )
            
            # Create task-specific configuration with scan context
            task_execution_config = {
                "scan_context": scan_context.to_dict(),
                "instance_id": f"{parent_instance_id}-{scan_context.scan_id}-{task_name}",
                "task": task_name,
                "task_index": i,
                "total_tasks": len(task_configs)
            }
            
            # Use prepared input from previous task - but only if it's not the first task
            if i > 0:  # Only set input_blob_path for tasks after the first one
                # Use the prepared input path: scans/domain-scan_id/task/in/input.txt
                task_execution_config["input_blob_path"] = f"scans/{scan_context.domain}-{scan_context.scan_id}/{task_name}/in/input.txt"
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
            
            logging.info(f"Completed task {task_name}, result: {task_result.get('aggregated_result')}")


        # After all tasks are done, store the final enumeration scan results
        httpx_blob_path = f"scans/{scan_context.domain}-{scan_context.scan_id}/httpx/out/final_out.json"
        dns_resolve_blob_path = f"scans/{scan_context.domain}-{scan_context.scan_id}/dns_resolve/out/final_out.json"

        yield context.call_activity(
            "save_enumeration_scan_results",
            {
                "scan_context": scan_context.to_dict(),
                "httpx_blob_path": httpx_blob_path,
                "dns_resolve_blob_path": dns_resolve_blob_path
            }
        )



        # Create final pipeline summary
        pipeline_summary = {
            "scan_id": scan_context.scan_id,
            "domain": scan_context.domain,
            "status": "completed",
            "total_tasks": len(task_configs),
            "completed_tasks": len(results),
            "task_results": results
        }
        
        logging.info(f"=== TASK PIPELINE ORCHESTRATOR COMPLETED === {pipeline_summary}")

        # After all done
        yield context.call_activity(
            "update_enumeration_scan_status",
            {"enumeration_scan_id": scan_context.scan_id, "status": "Completed"}
        )

        return pipeline_summary
        
    except Exception as e:
        logging.error(f"Task pipeline orchestrator failed: {str(e)}")
        logging.error(traceback.format_exc())
        raise 