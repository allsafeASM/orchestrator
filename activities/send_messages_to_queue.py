import logging
import json
import os
import traceback
import azure.functions as func
import azure.durable_functions as df
from azure.servicebus import ServiceBusClient, ServiceBusMessage
from azure.servicebus.exceptions import ServiceBusError

app = func.Blueprint()

@app.activity_trigger(input_name="payload")
async def send_messages_to_queue(payload: dict):
    logging.info("=== SEND MESSAGES TO QUEUE ACTIVITY STARTED ===")
    try:
        connection_string = os.environ.get("ServiceBusConnection")
        if not connection_string:
            raise ValueError("ServiceBusConnection environment variable not set")
        queue_name = payload.get("queue_name")
        messages = payload.get("messages", [])
        if not queue_name:
            raise ValueError("queue_name is required in payload")
        if not messages:
            logging.warning(f"No messages to send to queue '{queue_name}'")
            return {"success_count": 0, "error_count": 0, "errors": []}
        servicebus_client = ServiceBusClient.from_connection_string(connection_string)
        success_count = 0
        error_count = 0
        errors = []
        with servicebus_client:
            sender = servicebus_client.get_queue_sender(queue_name=queue_name)
            with sender:
                for i, message_data in enumerate(messages):
                    try:
                        message_body = json.dumps(message_data, ensure_ascii=False)
                        message = ServiceBusMessage(
                            body=message_body,
                            content_type="application/json"
                        )
                        sender.send_messages(message)
                        success_count += 1
                    except ServiceBusError as e:
                        error_count += 1
                        errors.append(f"Failed to send message {i+1}: {str(e)}")
                        logging.error(f"ServiceBusError: {str(e)}")
                    except Exception as e:
                        error_count += 1
                        errors.append(f"Unexpected error sending message {i+1}: {str(e)}")
                        logging.error(f"Exception: {str(e)}")
        result = {
            "success_count": success_count,
            "error_count": error_count,
            "total_messages": len(messages),
            "queue_name": queue_name,
            "errors": errors
        }
        logging.info(f"Queue operation completed: {success_count} successful, {error_count} failed")
        return result
    except Exception as e:
        logging.error(f"Failed to send messages to queue: {str(e)}")
        logging.error(traceback.format_exc())
        return {
            "success_count": 0,
            "error_count": len(payload.get("messages", [])),
            "total_messages": len(payload.get("messages", [])),
            "queue_name": payload.get("queue_name", "unknown"),
            "errors": [str(e)]
        }