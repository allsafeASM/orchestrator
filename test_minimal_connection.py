#!/usr/bin/env python3
"""
Minimal test to verify asyncpg connection with the same parameters that work with psql
"""

import asyncio
import asyncpg
import os

async def test_minimal_connection():
    """Test minimal asyncpg connection"""
    print("=== Testing Minimal asyncpg Connection ===")
    
    try:
        # Use the exact same parameters that work with psql
        conn = await asyncpg.connect(
            user='asm',
            password="GradProj'25@@",
            database='asm',
            host='asm-db-server.postgres.database.azure.com',
            port=5432,
            ssl='require'
        )
        
        print("✅ Connection successful!")
        
        # Test a simple query
        result = await conn.fetchval('SELECT version()')
        print(f"✅ Database version: {result}")
        
        await conn.close()
        print("✅ Connection closed successfully")
        
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        import traceback
        traceback.print_exc()

async def test_connection_string():
    """Test connection using connection string format"""
    print("\n=== Testing Connection String Format ===")
    
    try:
        # Build connection string manually
        conn_str = "postgresql://asm:GradProj'25@@@asm-db-server.postgres.database.azure.com:5432/asm?sslmode=require"
        
        conn = await asyncpg.connect(conn_str)
        
        print("✅ Connection string format successful!")
        
        result = await conn.fetchval('SELECT version()')
        print(f"✅ Database version: {result}")
        
        await conn.close()
        print("✅ Connection closed successfully")
        
    except Exception as e:
        print(f"❌ Connection string format failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_minimal_connection())
    asyncio.run(test_connection_string()) 