import logging
import json
import traceback
import azure.durable_functions as df
import azure.functions as func
from config.scan_context import ScanContext

app = func.Blueprint()

@app.orchestration_trigger(context_name="context")
def tool_stage_orchestrator(context: df.DurableOrchestrationContext):
    logging.info("=== TOOL STAGE ORCHESTRATOR STARTED ===")
    try:
        config = context.get_input()
        scan_context = ScanContext.from_dict(config["scan_context"])
        task = config["task"]
        instance_id = config["instance_id"]

        logging.info(f"Tool stage config: scan_id={scan_context.enum_scan_id}, {scan_context.vuln_scan_id}, task={task}, domain={scan_context.domain}, instance_id={instance_id}")

        if task == "nuclei":
            # 1. Network stage
            network_config = config.copy()
            network_config["type"] = "network"
            network_config["input_blob_path"] = f"scans/{scan_context.domain}-{scan_context.vuln_scan_id}/{config['task']}-network/in/input.txt"
            network_messages = yield context.call_activity("prepare_scan_messages", network_config)
            completion_tasks = [context.wait_for_external_event("nuclei_completed") for _ in network_messages]
            # 2. HTTP stage
            http_config = config.copy()
            http_config["type"] = "http"
            http_config["input_blob_path"] =  f"scans/{scan_context.domain}-{scan_context.vuln_scan_id}/{config['task']}-http/in/input.txt"
            http_messages = yield context.call_activity("prepare_scan_messages", http_config)
            all_messages = network_messages + http_messages
            yield context.call_activity("send_messages_to_queue", {
                "queue_name": "vuln-tasks",
                "messages": all_messages
            })
            completion_tasks = [context.wait_for_external_event("nuclei_completed") for _ in all_messages]
            yield context.task_all(completion_tasks)
            aggregated_result = yield context.call_activity("aggregate_stage_results", {
                "enum_scan_id": scan_context.enum_scan_id,
                "vuln_scan_id": scan_context.vuln_scan_id,
                "task": task,
                "domain": scan_context.domain
            })
            return {
                "success": True,
                "task": task,
                "enum_scan_id": scan_context.enum_scan_id,
                "vuln_scan_id": scan_context.vuln_scan_id,
                "domain": scan_context.domain,
                "messages_processed": len(network_messages) + len(http_messages),
                "aggregated_result": None
            }
        else:
            messages = yield context.call_activity("prepare_scan_messages", config)

            yield context.call_activity("send_messages_to_queue", {
                "queue_name": "tasks",
                "messages": messages
            })
            event_name = f"{task}_completed"
            # Wait for all completion events
            completion_tasks = []
            for _ in messages:
                completion_tasks.append(context.wait_for_external_event(event_name))
            yield context.task_all(completion_tasks)
            
            # Aggregate results for this task
            aggregated_result = yield context.call_activity("aggregate_stage_results", {
                "enum_scan_id": scan_context.enum_scan_id,
                "vuln_scan_id": scan_context.vuln_scan_id,
                "task": task,
                "domain": scan_context.domain
            })
            
            # Save results to database with the aggregated result path
            save_data = {
                "scan_context": scan_context.to_dict(),
                "task": task,
                "output_blob_path": aggregated_result
            }
            yield context.call_activity("save_to_database", save_data)
            
            return {
                "success": True,
                "task": task,
                "enum_scan_id": scan_context.enum_scan_id,
                "vuln_scan_id": scan_context.vuln_scan_id,
                "domain": scan_context.domain,
                "messages_processed": len(messages),
                "aggregated_result": aggregated_result
            }
    except Exception as e:
        logging.error(f"Tool stage orchestrator failed: {str(e)}")
        logging.error(traceback.format_exc())
        
        return {
            "success": False,
            "error": str(e),
            "task": task if 'task' in locals() else 'unknown',
            "enum_scan_id": scan_context.enum_scan_id if 'scan_context' in locals() else 'unknown',
            "vuln_scan_id": scan_context.vuln_scan_id if 'scan_context' in locals() else 'unknown',
            "domain": scan_context.domain if 'scan_context' in locals() else 'unknown'
        } 