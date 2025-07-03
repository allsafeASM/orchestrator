"""
Nuclei Progress Orchestrator
Handles nuclei execution with progress tracking based on completion events
"""
import logging
import traceback
import azure.durable_functions as df
import azure.functions as func
from config.scan_context import ScanContext

app = func.Blueprint()

@app.orchestration_trigger(context_name="context")
def nuclei_progress_orchestrator(context: df.DurableOrchestrationContext):
    logging.info("=== NUCLEI PROGRESS ORCHESTRATOR STARTED ===")
    try:
        initial_input = context.get_input()
        scan_context = ScanContext.from_dict(initial_input["scan_context"])
        task = initial_input.get("task", "nuclei")
        
        logging.info(f"Nuclei progress config: vuln_scan_id={scan_context.vuln_scan_id}, domain={scan_context.domain}")
        
        # Follow the same nuclei logic as tool_stage_orchestrator
        # 1. Network stage
        network_config = {
            "scan_context": scan_context.to_dict(),
            "task": task,
            "type": "network",
            "input_blob_path": f"scans/{scan_context.domain}-{scan_context.vuln_scan_id}/{task}-network/in/input.txt",
            **{k: v for k, v in initial_input.items() if k not in ["scan_context", "task", "input_blob_path"]}
        }
        network_messages = yield context.call_activity("prepare_scan_messages", network_config)
        
        # 2. HTTP stage
        http_config = {
            "scan_context": scan_context.to_dict(),
            "task": task,
            "type": "http",
            "input_blob_path": f"scans/{scan_context.domain}-{scan_context.vuln_scan_id}/{task}-http/in/input.txt",
            **{k: v for k, v in initial_input.items() if k not in ["scan_context", "task", "input_blob_path"]}
        }
        http_messages = yield context.call_activity("prepare_scan_messages", http_config)
        
        # Send all messages to vuln-tasks queue
        all_messages = network_messages + http_messages
        yield context.call_activity("send_messages_to_queue", {
            "queue_name": "vuln-tasks",
            "messages": all_messages
        })
        
        # Track progress based on completion events
        event_name = f"{task}_completed"
        total_messages = len(all_messages)
        completed_events = 0
        
        logging.info(f"Waiting for {total_messages} completion events for {task} (network: {len(network_messages)}, http: {len(http_messages)})")
        
        # Wait for completion events one by one and update progress
        prev_progress = 0

        for i in range(total_messages):
            # Wait for the next completion event
            yield context.wait_for_external_event(event_name)
            completed_events += 1
            
            # Calculate current progress percentage
            progress_percentage = int((completed_events / total_messages) * 100)
            logging.info(f"Nuclei progress: {completed_events}/{total_messages} events ({progress_percentage}%)")
            
            # Update progress every 10% or at the end
            if progress_percentage - prev_progress > 5 or completed_events == len(all_messages):
                prev_progress = progress_percentage
                yield context.call_activity(
                    "update_vulnerability_scan_progress",
                    {
                        "vulnerability_scan_id": scan_context.vuln_scan_id,
                        "progress_percentage": progress_percentage
                    }
                )
        
        # Final progress update (100%)
        progress_percentage = 100
        logging.info(f"Nuclei completed: {completed_events}/{total_messages} events (100%)")
        
        # Update vulnerability scan status
        yield context.call_activity(
            "update_vulnerability_scan_status",
            {
                "vulnerability_scan_id": scan_context.vuln_scan_id,
                "status": "Completed"
            }
        )
        
        # Aggregate results for nuclei
        aggregated_result = yield context.call_activity("aggregate_stage_results", {
            "enum_scan_id": scan_context.enum_scan_id,
            "vuln_scan_id": scan_context.vuln_scan_id,
            "task": task,
            "domain": scan_context.domain
        })
        
        result = {
            "success": True,
            "task": task,
            "enum_scan_id": scan_context.enum_scan_id,
            "vuln_scan_id": scan_context.vuln_scan_id,
            "domain": scan_context.domain,
            "messages_processed": total_messages,
            "aggregated_result": aggregated_result,
            "total_completion_events": completed_events,
            "expected_completion_events": total_messages,
            "final_progress": progress_percentage
        }
        
        logging.info(f"=== NUCLEI PROGRESS ORCHESTRATOR COMPLETED === {result}")
        return result
        
    except Exception as e:
        logging.error(f"Nuclei progress orchestrator failed: {str(e)}")
        logging.error(traceback.format_exc())
        raise 