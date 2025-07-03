# Azure Functions v2 Programming Model
import azure.functions as func
import azure.durable_functions as df

from orchestrators.main_orchestrator import app as main_orchestrator_blueprint
from orchestrators.task_pipeline_orchestrator import app as task_pipeline_orchestrator_blueprint
from orchestrators.tool_stage_orchestrator import app as tool_stage_orchestrator_blueprint

from activities.prepare_scan_messages import app as prepare_scan_messages_blueprint
from activities.send_messages_to_queue import app as send_messages_to_queue_blueprint
from activities.aggregate_stage_results import app as aggregate_stage_results_blueprint
from activities.save_to_database import app as save_to_database_blueprint
from activities.validate_domain import app as validate_domain_blueprint
from activities.save_enumeration_scan_results import app as save_enumeration_scan_results_blueprint
from activities.update_enumeration_scan_status import app as update_enumeration_scan_status_blueprint
app = func.FunctionApp()

# Register all blueprints using the correct v2 method
app.register_blueprint(main_orchestrator_blueprint)
app.register_blueprint(task_pipeline_orchestrator_blueprint)
app.register_blueprint(tool_stage_orchestrator_blueprint)
app.register_blueprint(prepare_scan_messages_blueprint)
app.register_blueprint(send_messages_to_queue_blueprint)
app.register_blueprint(aggregate_stage_results_blueprint)
app.register_blueprint(save_to_database_blueprint)
app.register_blueprint(validate_domain_blueprint)
app.register_blueprint(save_enumeration_scan_results_blueprint)
app.register_blueprint(update_enumeration_scan_status_blueprint)

# HTTP trigger to start the orchestration
@app.route(route="orchestrators/start_scan", methods=["POST"])
@app.function_name("start_scan_orchestrator")
@app.durable_client_input(client_name="client")
async def start_scan_orchestrator(req: func.HttpRequest, client: df.DurableOrchestrationClient) -> func.HttpResponse:
    import logging, json, traceback
    logging.info("=== START SCAN ORCHESTRATOR TRIGGERED ===")
    try:
        body = req.get_json()
        logging.info(f"Request body received: {json.dumps(body, indent=2)}")
        required_fields = ['enum_scan_id', 'domain', 'user_id']
        if not body.get('user_id'):
            body['user_id'] = 11
        missing_fields = [field for field in required_fields if field not in body]
        if missing_fields:
            error_msg = f"Missing required fields: {missing_fields}"
            logging.error(error_msg)
            return func.HttpResponse(error_msg, status_code=400)
        
        # Optional: allow custom task sequence
        if 'task_sequence' in body:
            logging.info(f"Custom task sequence provided: {body['task_sequence']}")
        
        logging.info(f"Starting orchestration for scan_id: {body['enum_scan_id']}, domain: {body['domain']}, user_id: {body['user_id']}")
        instance_id = await client.start_new("main_orchestrator", client_input=body)
        logging.info(f"Successfully started orchestration with ID = '{instance_id}'")
        response = client.create_check_status_response(req, instance_id)
        logging.info(f"Created check status response for instance: {instance_id}")
        return response
    except Exception as e:
        error_msg = f"Failed to start scan orchestrator: {str(e)}"
        logging.error(error_msg)
        logging.error(f"Exception details: {traceback.format_exc()}")
        return func.HttpResponse(error_msg, status_code=500)