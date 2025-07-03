"""
Scan Context - Eliminates prop drilling by centralizing scan metadata
"""
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict


@dataclass
class ScanContext:
    """Centralized scan context to eliminate prop drilling"""
    enum_scan_id: str
    vuln_scan_id: str
    domain: str
    domain_id: int
    user_id: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for serialization"""
        return asdict(obj=self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ScanContext':
        """Create context from dictionary"""
        return cls(
            enum_scan_id=data['enum_scan_id'],
            vuln_scan_id=data['vuln_scan_id'],
            domain=data['domain'],
            domain_id=data['domain_id'],
            user_id=data.get('user_id')
        )
    
    # def get_blob_path(self, task: str, extension: str, path_type: str = "out") -> str:
    #     """Generate standardized blob path for this scan context"""
    #     if path_type == "out":
    #         return f"scans/{self.domain}-{self.vuln_scan_id if task == "nuclei" else self.enum_scan_id }/{task}/out/final_out.{extension}"
    #     elif path_type == "in":
    #         return f"scans/{self.domain}-{self.vuln_scan_id if task == "nuclei" else self.enum_scan_id }/{task}/in/input.txt"
    #     else:
    #         raise ValueError(f"Invalid path_type: {path_type}")
    
    def get_chunk_path(self, task: str, chunk_index: int, type=None) -> str:
        """Generate chunk blob path for this scan context"""
        if task == 'nuclei':
            return f"{self.domain}-{self.vuln_scan_id}/{task}-{type}/in/chunk_{chunk_index:04d}.txt" 
        return f"{self.domain}-{self.enum_scan_id}/{task}/in/chunk_{chunk_index:04d}.txt" 