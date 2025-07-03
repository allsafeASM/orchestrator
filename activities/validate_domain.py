import logging
import traceback
import azure.functions as func
import azure.durable_functions as df
from config.scan_context import ScanContext
from database.db_manager import DatabaseManager
import asyncio

app = func.Blueprint()

@app.activity_trigger(input_name="payload")
async def validate_domain(payload: dict):
    """
    Validate that domain exists in database and belongs to the specified user.
    
    Expected data format:
    {
        "scan_context": {
            "scan_id": "scan_123",
            "domain": "example.com",
            "domain_id": null,
            "user_id": 123
        }
    }
    
    Returns:
    {
        "valid": True,
        "domain_id": 456,
        "domain": "example.com"
    }
    """
    logging.info("=== VALIDATE DOMAIN ACTIVITY STARTED ===")
    try:
        scan_context = ScanContext.from_dict(payload["scan_context"])
        domain = scan_context.domain
        user_id = scan_context.user_id
        
        if not user_id:
            error_msg = "user_id is required for domain validation"
            logging.error(error_msg)
            return {
                "valid": False,
                "error": error_msg,
                "domain_id": None
            }
        
        logging.info(f"Validating domain: {domain} for user: {user_id}")
        
        # Get database manager instance
        db_manager = DatabaseManager()
        
        # Check if domain exists in database and belongs to the user
        domain_id = await db_manager.get_domain_id_by_user(domain, user_id)
        
        if not domain_id:
            error_msg = f"Domain '{domain}' not found in database for user {user_id}"
            logging.error(error_msg)
            
            return {
                "valid": False,
                "error": error_msg,
                "domain_id": None
            }
        
        logging.info(f"Domain '{domain}' validated successfully for user {user_id}. Domain ID: {domain_id}")
        
        return {
            "valid": True,
            "domain_id": domain_id,
            "domain": domain
        }
        
    except Exception as e:
        error_msg = f"Domain validation failed: {str(e)}"
        logging.error(error_msg)
        logging.error(traceback.format_exc())
        
        return {
            "valid": False,
            "error": error_msg,
            "domain_id": None
        } 