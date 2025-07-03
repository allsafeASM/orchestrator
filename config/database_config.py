"""
Database configuration settings for the security scanning system.
"""

import os
from typing import Optional, Dict, Any

class DatabaseConfig:
    """Configuration class for database settings."""
    
    @classmethod
    def get_connection_params(cls) -> Dict[str, Any]:
        """Get PostgreSQL connection parameters as a dictionary."""
        return {
            'host': os.getenv('POSTGRES_HOST'),
            'port': int(os.getenv('POSTGRES_PORT', '5432')),
            'database': os.getenv('POSTGRES_DATABASE', 'allsafe_asm'),
            'user': os.getenv('POSTGRES_USER'),
            'password': os.getenv('POSTGRES_PASSWORD'),
            'ssl': os.getenv('POSTGRES_SSL_MODE', 'require')
        }
    
    @classmethod
    def get_connection_string(cls) -> str:
        """Get PostgreSQL connection string."""
        postgres_connection_string = os.getenv('POSTGRES_CONNECTION_STRING')
        if postgres_connection_string:
            return postgres_connection_string
        
        host = os.getenv('POSTGRES_HOST')
        port = os.getenv('POSTGRES_PORT', '5432')
        database = os.getenv('POSTGRES_DATABASE', 'allsafe_asm')
        user = os.getenv('POSTGRES_USER')
        password = os.getenv('POSTGRES_PASSWORD')
        ssl_mode = os.getenv('POSTGRES_SSL_MODE', 'require')
        
        if all([host, user, password]):
            return f"postgresql://{user}:{password}@{host}:{port}/{database}?sslmode={ssl_mode}"
        
        return None
    
    @classmethod
    def is_configured(cls) -> bool:
        """Check if PostgreSQL is properly configured."""
        params = cls.get_connection_params()
        return all([params['host'], params['user'], params['password']])
    
    @classmethod
    def get_database_info(cls) -> dict:
        """Get database configuration information."""
        return {
            "postgres_configured": cls.is_configured(),
            "host": os.getenv('POSTGRES_HOST'),
            "database": os.getenv('POSTGRES_DATABASE', 'allsafe_asm'),
            "port": os.getenv('POSTGRES_PORT', '5432'),
            "ssl_mode": os.getenv('POSTGRES_SSL_MODE', 'require')
        } 