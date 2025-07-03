"""
Task Configuration Registry
Centralized configuration for all security scanning tasks
"""
from typing import Dict, Any, Optional, List

class TaskConfig:
    """Base configuration class for all tasks"""
    def __init__(self, 
                 task_name: str,
                 description: str = "",
                 input_blob_path: Optional[str] = None,
                 previous_output_path: Optional[str] = None,
                 output_format: str = "json",
                 timeout_minutes: int = 30,
                 retry_count: int = 3,
                 prepare_next_input: bool = False,
                 **kwargs):
        self.task_name = task_name
        self.description = description
        self.input_blob_path = input_blob_path
        self.previous_output_path = previous_output_path
        self.output_format = output_format
        self.timeout_minutes = timeout_minutes
        self.retry_count = retry_count
        self.prepare_next_input = prepare_next_input
        # Store any additional task-specific parameters
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary for serialization"""
        config = {
            "task_name": self.task_name,
            "description": self.description,
            "output_format": self.output_format,
            "timeout_minutes": self.timeout_minutes,
            "retry_count": self.retry_count,
            "prepare_next_input": self.prepare_next_input
        }
        if self.input_blob_path:
            config["input_blob_path"] = self.input_blob_path
        
        if self.previous_output_path:
            config["previous_output_path"] = self.previous_output_path
        
        # Add any additional attributes
        for key, value in self.__dict__.items():
            if key not in config and not key.startswith('_'):
                config[key] = value
        
        return config

# Task Configuration Registry
TASK_REGISTRY = {
    "subfinder": TaskConfig(
        task_name="subfinder",
        description="Discovering Subdomains",
        output_format="txt",
        split_threshold=None,  # No splitting for subfinder
        input_blob_path=None,  # No input required
        estimated_duration=300,  # 5 minutes
        prepare_next_input=True  # subfinder prepares input for dns_resolve
    ),
    
    "dns_resolve": TaskConfig(
        task_name="dns_resolve",
        description="DNS Resolution",
        output_format="json",
        split_threshold=100,  # Process 100 subdomains per chunk
        input_blob_path="subfinder",  # Uses prepared input from subfinder task
        estimated_duration=600,  # 10 minutes
        prepare_next_input=True  # dns_resolve prepares input for port_scan
    ),
    
    "port_scan": TaskConfig(
        task_name="port_scan",
        description="Port Scanning",
        output_format="txt",
        split_threshold=50,  # Process 10 IPs per chunk
        input_blob_path="dns_resolve",  # Uses prepared input from dns_resolve task
        estimated_duration=1800,  # 30 minutes
        prepare_next_input=True  # port_scan prepares input for httpx
    ),
    
    "httpx": TaskConfig(
        task_name="httpx",
        description="Enumerating Web Servers",
        output_format="json",
        split_threshold=50,  # Process 50 hosts per chunk
        input_blob_path="port_scan",  # Uses prepared input from port_scan task
        estimated_duration=900,  # 15 minutes
        prepare_next_input=True  # httpx prepares input for nuclei
    ),
    
    "nuclei": TaskConfig(
        task_name="nuclei",
        description="Vulnerability Scanning",
        input_blob_path="httpx",  # Uses prepared input from httpx task
        output_format="json",
        timeout_minutes=90,
        retry_count=1,
        severity="low,medium,high,critical",  # Task-specific parameter
        templates="cves,vulnerabilities,misconfiguration",
        split_threshold=30,
        prepare_next_input=False  # nuclei is the last task
    )
}

def get_task_config(task_name: str) -> Optional[TaskConfig]:
    """Get task configuration by name"""
    return TASK_REGISTRY.get(task_name)

def get_task_sequence(task_names: List[str]) -> List[TaskConfig]:
    """Get configurations for a sequence of tasks"""
    return [get_task_config(task) for task in task_names if get_task_config(task)]

def get_default_scan_sequence() -> List[str]:
    """Get the default sequence of tasks for a complete scan"""
    return ["subfinder", "dns_resolve", "port_scan", "httpx"]

def add_task_config(task_name: str, config: TaskConfig):
    """Add a new task configuration to the registry"""
    TASK_REGISTRY[task_name] = config 