#!/usr/bin/env python3
"""
Test script to verify database connection using settings from local.settings.json
"""

import json
import os
import asyncio
from database.db_manager import DatabaseManager

def load_local_settings():
    """Load settings from local.settings.json"""
    try:
        with open('local.settings.json', 'r') as f:
            settings = json.load(f)
            return settings.get('Values', {})
    except Exception as e:
        print(f"Error loading local.settings.json: {e}")
        return {}

async def test_database_connection():
    """Test database connection"""
    print("=== Database Connection Test ===")
    
    # Load settings from local.settings.json
    settings = load_local_settings()
    
    # Set environment variables
    for key, value in settings.items():
        os.environ[key] = value
    
    print("Environment variables set:")
    print(f"POSTGRES_HOST: {os.getenv('POSTGRES_HOST')}")
    print(f"POSTGRES_DATABASE: {os.getenv('POSTGRES_DATABASE')}")
    print(f"POSTGRES_USER: {os.getenv('POSTGRES_USER')}")
    print(f"POSTGRES_PORT: {os.getenv('POSTGRES_PORT')}")
    
    try:
        # Create database manager
        db_manager = DatabaseManager()
        
        # Test connection by trying to get a domain
        domain_id = await db_manager.get_domain_id("test.com")
        print(f"Database connection successful! Domain ID for test.com: {domain_id}")
        
        # Close the connection
        await db_manager.close()
        
    except Exception as e:
        print(f"Database connection failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_database_connection()) 