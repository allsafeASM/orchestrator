"""
Database utility functions for common operations and data formatting.
"""

import logging
import json
import os
from typing import List, Dict, Any, Optional
from datetime import datetime
from azure.storage.blob import BlobServiceClient
from .db_manager import db_manager


def read_blob_file(blob_path: str) -> str:
    """
    Read content from a blob file.
    
    Args:
        blob_path: Path to the blob file (e.g., "scans/example.com-scan-123/subfinder/out/final_out.txt")
        
    Returns:
        str: Content of the blob file
    """
    try:
        # Get connection string from environment
        connection_string = os.getenv('AzureStorageConnectionString')
        if not connection_string:
            raise ValueError("AzureStorageConnectionString not configured")
        
        # Parse blob path
        if '/' not in blob_path:
            raise ValueError(f"Invalid blob path: {blob_path}")
        
        container_name = blob_path.split('/')[0]
        blob_name = '/'.join(blob_path.split('/')[1:])
        
        # Create blob client
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_client = blob_service_client.get_container_client(container_name)
        blob_client = container_client.get_blob_client(blob_name)
        
        # Download blob content
        blob_data = blob_client.download_blob()
        content = blob_data.readall().decode('utf-8')
        
        logging.info(f"Successfully read blob file: {blob_path}")
        return content
        
    except Exception as e:
        logging.error(f"Failed to read blob file {blob_path}: {str(e)}")
        raise


def format_subfinder_results(subfinder_output: str, domain: str) -> List[str]:
    """
    Format subfinder output into a clean list of subdomains.
    
    Args:
        subfinder_output: Raw output from subfinder tool
        domain: The main domain being scanned
        
    Returns:
        List[str]: Clean list of subdomains
    """
    try:
        # Split by newlines and clean up
        subdomains = []
        for line in subfinder_output.strip().split('\n'):
            line = line.strip()
            if line and domain in line:
                # Remove any extra whitespace or special characters
                clean_subdomain = line.split()[0] if line.split() else line
                subdomains.append(clean_subdomain)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_subdomains = []
        for subdomain in subdomains:
            if subdomain not in seen:
                seen.add(subdomain)
                unique_subdomains.append(subdomain)
        
        logging.info(f"Formatted {len(unique_subdomains)} unique subdomains from subfinder output")
        return unique_subdomains
        
    except Exception as e:
        logging.error(f"Failed to format subfinder results: {str(e)}")
        return []


def format_dns_resolve_results(dns_resolve_output: str) -> Dict[str, Dict[str, any]]:
    """
    Format dns_resolve output into structured results.
    
    Args:
        dns_resolve_output: JSON output from dns_resolve tool with DnsxOutput structure
        
    Returns:
        Dict mapping subdomain to its resolution info including status
    """
    try:
        # Parse JSON output from dns_resolve
        dns_resolve_data = json.loads(dns_resolve_output)
        
        if not isinstance(dns_resolve_data, dict) or 'records' not in dns_resolve_data:
            logging.error("Invalid dns_resolve output format: missing 'records' field")
            return {}
        
        records = dns_resolve_data['records']
        formatted_results = {}
        
        for subdomain, resolution_info_list in records.items():
            if not isinstance(resolution_info_list, list):
                continue
                
            # Combine all resolution info for this subdomain
            all_a_records = []
            all_cname_records = []
            dns_status = 'unknown'  # Default status
            
            for resolution_info in resolution_info_list:
                if isinstance(resolution_info, dict):
                    # Extract A records
                    a_records = resolution_info.get('A', [])
                    if isinstance(a_records, list):
                        all_a_records.extend(a_records)
                    
                    # Extract CNAME records
                    cname_records = resolution_info.get('CNAME', [])
                    if isinstance(cname_records, list):
                        all_cname_records.extend(cname_records)
                    
                    # Extract status (use the first non-empty status found)
                    status = resolution_info.get('status', '')
                    if status and dns_status == 'unknown':
                        dns_status = status
            
            # Remove duplicates
            all_a_records = list(set(all_a_records))
            all_cname_records = list(set(all_cname_records))
            
            # Determine status based on resolution results
            if all_a_records or all_cname_records:
                if dns_status == 'unknown':
                    dns_status = 'resolved'
            else:
                dns_status = 'unresolved'
            
            formatted_results[subdomain] = {
                'A': all_a_records,
                'CNAME': all_cname_records,
                'status': dns_status
            }
        
        logging.info(f"Formatted dns_resolve results: {len(formatted_results)} subdomains")
        return formatted_results
        
    except Exception as e:
        logging.error(f"Failed to format dns_resolve results: {str(e)}")
        return {}


def format_nmap_results(nmap_output: str) -> Dict[str, List[int]]:
    """
    Format nmap output into structured port scan results.
    
    Args:
        nmap_output: Raw output from nmap tool
        
    Returns:
        Dict with 'open_ports' and 'web_ports' lists
    """
    try:
        open_ports = []
        web_ports = []
        lines = nmap_output.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if 'open' in line.lower() and 'tcp' in line.lower():
                # Parse nmap port line (e.g., "80/tcp open http")
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0].split('/')
                    if len(port_info) == 2:
                        try:
                            port = int(port_info[0])
                            open_ports.append(port)
                            
                            # Check if it's a web port
                            service = parts[2].lower() if len(parts) > 2 else ""
                            if service in ['http', 'https', 'http-proxy', 'http-alt'] or port in [80, 443, 8080, 8443]:
                                web_ports.append(port)
                        except ValueError:
                            continue
        
        # Remove duplicates
        open_ports = list(set(open_ports))
        web_ports = list(set(web_ports))
        
        logging.info(f"Formatted nmap results: {len(open_ports)} open ports, {len(web_ports)} web ports")
        return {
            "open_ports": open_ports,
            "web_ports": web_ports
        }
        
    except Exception as e:
        logging.error(f"Failed to format nmap results: {str(e)}")
        return {"open_ports": [], "web_ports": []}


def format_httpx_results(httpx_output: str) -> List[Dict[str, Any]]:
    """
    Format httpx output into structured webserver data.
    
    Args:
        httpx_output: Raw output from httpx tool (JSON format expected)
        
    Returns:
        List[Dict]: Structured webserver data
    """
    try:
        # Parse JSON output from httpx
        if httpx_output.strip():
            results = json.loads(httpx_output)
            if isinstance(results, list):
                webservers = []
                for result in results:
                    webserver = {
                        "url": result.get("url", ""),
                        "port": result.get("port", 80),
                        "webserver": result.get("webserver", ""),
                        "title": result.get("title", ""),
                        "status_code": result.get("status_code"),
                        "content_length": result.get("content_length"),
                        "technologies": result.get("technologies", [])
                    }
                    webservers.append(webserver)
                
                logging.info(f"Formatted httpx results: {len(webservers)} webservers")
                return webservers
        
        return []
        
    except Exception as e:
        logging.error(f"Failed to format httpx results: {str(e)}")
        return []


async def store_subfinder_task(domain_id: int, output_blob_path: str, domain: str) -> Dict[str, Any]:
    """
    Complete subfinder task: read blob file, format and store subdomains.
    
    Args:
        domain_id: ID of the domain in the domains table
        output_blob_path: Blob path to subfinder output file
        domain: The main domain being scanned
        
    Returns:
        Dict with success status and results
    """
    try:
        # Read subfinder output from blob
        subfinder_output = read_blob_file(output_blob_path)
        
        # Format subfinder output
        subdomain_names = format_subfinder_results(subfinder_output, domain)
        
        if not subdomain_names:
            return {"success": False, "error": "No subdomains found in subfinder output"}
        
        # Store in database using batch operations
        result = await db_manager.store_subdomains_from_subfinder(domain_id, subdomain_names)
        
        return result
        
    except Exception as e:
        logging.error(f"Failed to complete subfinder task: {str(e)}")
        return {"success": False, "error": str(e)}


async def store_dns_resolve_task(domain_id: int, output_blob_path: str) -> Dict[str, Any]:
    """
    Complete DNS resolve task: read blob file, format and store all DNS records and IPs at once.
    
    Args:
        domain_id: ID of the domain in the domains table
        output_blob_path: Blob path to dns_resolve output file
        
    Returns:
        Dict with success status and results
    """
    try:
        # Read dns_resolve output from blob
        dns_resolve_output = read_blob_file(output_blob_path)
        
        # Format dns_resolve output
        dns_results = format_dns_resolve_results(dns_resolve_output)
        
        if not dns_results:
            return {"success": False, "error": "No DNS resolution results found"}
        
        # Store all DNS results in a single batch operation
        result = await db_manager.store_dns_resolve_results_batch(domain_id, dns_results)
        
        return result
        
    except Exception as e:
        logging.error(f"Failed to complete DNS resolve task: {str(e)}")
        return {"success": False, "error": str(e)}


async def store_port_scan_task(ip_address: str, output_blob_path: str) -> Dict[str, Any]:
    """
    Complete port scan task: read blob file, format and store open ports.
    
    Args:
        ip_address: The IP address that was scanned
        output_blob_path: Blob path to nmap output file
        
    Returns:
        Dict with success status and results
    """
    try:
        # Read nmap output from blob
        nmap_output = read_blob_file(output_blob_path)
        
        # Format nmap output
        port_results = format_nmap_results(nmap_output)
        
        if not port_results["open_ports"]:
            return {"success": False, "error": "No open ports found in nmap output"}
        
        # Store in database using batch operations
        result = await db_manager.store_port_scan_results(
            ip_address=ip_address,
            open_ports=port_results["open_ports"],
            web_ports=port_results["web_ports"]
        )
        
        return result
        
    except Exception as e:
        logging.error(f"Failed to complete port scan task: {str(e)}")
        return {"success": False, "error": str(e)}


async def store_httpx_task(subdomain_id: int, output_blob_path: str) -> Dict[str, Any]:
    """
    Complete httpx task: read blob file, format and store webservers and technologies.
    
    Args:
        subdomain_id: ID of the subdomain in the subdomains table
        output_blob_path: Blob path to httpx output file
        
    Returns:
        Dict with success status and results
    """
    try:
        # Read httpx output from blob
        httpx_output = read_blob_file(output_blob_path)
        
        # Format httpx output
        webserver_data = format_httpx_results(httpx_output)
        
        if not webserver_data:
            return {"success": False, "error": "No webserver data found in httpx output"}
        
        # Store in database using batch operations
        result = await db_manager.store_httpx_results(subdomain_id, webserver_data)
        
        return result
        
    except Exception as e:
        logging.error(f"Failed to complete httpx task: {str(e)}")
        return {"success": False, "error": str(e)}


# ==================== BATCH PROCESSING FUNCTIONS ====================

async def store_subfinder_batch(domain_id: int, output_blob_paths: List[str], domain: str) -> Dict[str, Any]:
    """
    Process multiple subfinder outputs in batch for better performance.
    
    Args:
        domain_id: ID of the domain in the domains table
        output_blob_paths: List of blob paths to subfinder output files
        domain: The main domain being scanned
        
    Returns:
        Dict with success status and combined results
    """
    try:
        all_subdomains = []
        
        # Read and format all subfinder outputs
        for blob_path in output_blob_paths:
            try:
                subfinder_output = read_blob_file(blob_path)
                subdomains = format_subfinder_results(subfinder_output, domain)
                all_subdomains.extend(subdomains)
            except Exception as e:
                logging.error(f"Failed to process subfinder blob {blob_path}: {str(e)}")
                continue
        
        # Remove duplicates across all outputs
        unique_subdomains = list(dict.fromkeys(all_subdomains))  # Preserves order
        
        if not unique_subdomains:
            return {"success": False, "error": "No subdomains found in any subfinder output"}
        
        # Store all subdomains in a single batch operation
        result = await db_manager.store_subdomains_from_subfinder(domain_id, unique_subdomains)
        
        return result
        
    except Exception as e:
        logging.error(f"Failed to complete subfinder batch task: {str(e)}")
        return {"success": False, "error": str(e)}


async def store_dns_resolve_batch(domain_id: int, output_blob_paths: List[str]) -> Dict[str, Any]:
    """
    Process multiple dns_resolve outputs in batch.
    
    Args:
        domain_id: ID of the domain in the domains table
        output_blob_paths: List of blob paths to dns_resolve output files
        
    Returns:
        Dict with success status and combined results
    """
    try:
        all_dns_results = {}
        
        # Read and format all dns_resolve outputs
        for blob_path in output_blob_paths:
            try:
                dns_resolve_output = read_blob_file(blob_path)
                dns_results = format_dns_resolve_results(dns_resolve_output)
                
                # Merge results (later results override earlier ones for same subdomain)
                all_dns_results.update(dns_results)
                
            except Exception as e:
                logging.error(f"Failed to process dns_resolve blob {blob_path}: {str(e)}")
                continue
        
        if not all_dns_results:
            return {"success": False, "error": "No DNS resolution results found in any dns_resolve output"}
        
        # Store all DNS results in a single batch operation
        result = await db_manager.store_dns_resolve_results_batch(domain_id, all_dns_results)
        
        return result
        
    except Exception as e:
        logging.error(f"Failed to complete DNS resolve batch task: {str(e)}")
        return {"success": False, "error": str(e)}


async def store_port_scan_batch(ip_scan_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process multiple port scan results in batch.
    
    Args:
        ip_scan_data: List of dicts with 'ip_address' and 'output_blob_path'
        
    Returns:
        Dict with success status and combined results
    """
    try:
        all_results = {
            "total_created_ports": 0,
            "processed_ips": 0,
            "errors": []
        }
        
        # Process each IP's port scan data
        for data in ip_scan_data:
            try:
                ip_address = data["ip_address"]
                output_blob_path = data["output_blob_path"]
                
                # Read and format nmap output
                nmap_output = read_blob_file(output_blob_path)
                port_results = format_nmap_results(nmap_output)
                
                if port_results["open_ports"]:
                    # Store in database
                    result = await db_manager.store_port_scan_results(
                        ip_address=ip_address,
                        open_ports=port_results["open_ports"],
                        web_ports=port_results["web_ports"]
                    )
                    
                    if result["success"]:
                        all_results["total_created_ports"] += result["created_port_count"]
                        all_results["processed_ips"] += 1
                    else:
                        all_results["errors"].append(f"Failed for IP {ip_address}: {result['error']}")
                else:
                    all_results["errors"].append(f"No open ports found for IP {ip_address}")
                    
            except Exception as e:
                all_results["errors"].append(f"Error processing IP {data.get('ip_address', 'unknown')}: {str(e)}")
        
        success = len(all_results["errors"]) == 0
        return {
            "success": success,
            "results": all_results,
            "error": "; ".join(all_results["errors"]) if all_results["errors"] else None
        }
        
    except Exception as e:
        logging.error(f"Failed to complete port scan batch task: {str(e)}")
        return {"success": False, "error": str(e)}


async def store_httpx_batch(subdomain_webserver_data: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process multiple httpx results in batch.
    
    Args:
        subdomain_webserver_data: List of dicts with 'subdomain_id' and 'output_blob_path'
        
    Returns:
        Dict with success status and combined results
    """
    try:
        all_results = {
            "total_created_webservers": 0,
            "total_created_technologies": 0,
            "total_created_relationships": 0,
            "processed_subdomains": 0,
            "errors": []
        }
        
        # Process each subdomain's webserver data
        for data in subdomain_webserver_data:
            try:
                subdomain_id = data["subdomain_id"]
                output_blob_path = data["output_blob_path"]
                
                # Read and format httpx output
                httpx_output = read_blob_file(output_blob_path)
                webserver_data = format_httpx_results(httpx_output)
                
                if webserver_data:
                    # Store in database
                    result = await db_manager.store_httpx_results(subdomain_id, webserver_data)
                    
                    if result["success"]:
                        all_results["total_created_webservers"] += result["created_webserver_count"]
                        all_results["total_created_technologies"] += result["created_technology_count"]
                        all_results["total_created_relationships"] += result["created_relationship_count"]
                        all_results["processed_subdomains"] += 1
                    else:
                        all_results["errors"].append(f"Failed for subdomain {subdomain_id}: {result['error']}")
                else:
                    all_results["errors"].append(f"No webserver data found for subdomain {subdomain_id}")
                    
            except Exception as e:
                all_results["errors"].append(f"Error processing subdomain {data.get('subdomain_id', 'unknown')}: {str(e)}")
        
        success = len(all_results["errors"]) == 0
        return {
            "success": success,
            "results": all_results,
            "error": "; ".join(all_results["errors"]) if all_results["errors"] else None
        }
        
    except Exception as e:
        logging.error(f"Failed to complete httpx batch task: {str(e)}")
        return {"success": False, "error": str(e)}


async def get_scan_progress(domain_id: int) -> Dict[str, Any]:
    """
    Get scan progress for a domain.
    
    Args:
        domain_id: ID of the domain in the domains table
        
    Returns:
        Dict with scan progress information
    """
    try:
        # This would need to be implemented in db_manager
        # For now, return a basic structure
        return {
            "domain_id": domain_id,
            "subdomains_count": 0,
            "resolved_ips_count": 0,
            "open_ports_count": 0,
            "webservers_count": 0,
            "technologies_count": 0
        }
        
    except Exception as e:
        logging.error(f"Failed to get scan progress: {str(e)}")
        return {"error": str(e)}


def create_scan_summary(domain_id: int, results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a comprehensive scan summary.
    
    Args:
        domain_id: ID of the domain in the domains table
        results: Dictionary containing all scan results
        
    Returns:
        Dict: Comprehensive scan summary
    """
    try:
        summary = {
            "domain_id": domain_id,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "total_subdomains": results.get("subdomains_count", 0),
            "total_ips": results.get("ips_count", 0),
            "total_open_ports": results.get("ports_count", 0),
            "total_webservers": results.get("webservers_count", 0),
            "total_technologies": results.get("technologies_count", 0),
            "scan_status": "completed"
        }
        
        logging.info(f"Created scan summary for domain {domain_id}")
        return summary
        
    except Exception as e:
        logging.error(f"Failed to create scan summary: {str(e)}")
        return {"error": str(e)}


# Legacy function for backward compatibility
def store_tool_results(scan_id: str, domain: str, tool_name: str, 
                      tool_output: str, metadata: Optional[Dict] = None) -> bool:
    """
    Legacy function for backward compatibility.
    This function is deprecated - use the specific task functions instead.
    """
    logging.warning("store_tool_results is deprecated. Use specific task functions instead.")
    return False


def format_nuclei_results(nuclei_output: str) -> List[Dict[str, Any]]:
    """
    Format nuclei output into structured vulnerability results.
    
    Args:
        nuclei_output: Raw output from nuclei tool (JSON format expected)
        
    Returns:
        List[Dict]: Structured vulnerability results
    """
    try:
        # Parse JSON output from nuclei
        if nuclei_output.strip():
            results = json.loads(nuclei_output)
            if isinstance(results, list):
                vulnerabilities = []
                for result in results:
                    vuln = {
                        "template_id": result.get("template-id", ""),
                        "template_name": result.get("template", ""),
                        "severity": result.get("info", {}).get("severity", "info"),
                        "target": result.get("host", ""),
                        "matched_at": result.get("matched-at", ""),
                        "extracted_results": result.get("extracted-results", []),
                        "matcher_name": result.get("matcher-name", ""),
                        "description": result.get("info", {}).get("description", ""),
                        "reference": result.get("info", {}).get("reference", []),
                        "tags": result.get("info", {}).get("tags", []),
                        "raw_result": result
                    }
                    vulnerabilities.append(vuln)
                
                logging.info(f"Formatted {len(vulnerabilities)} vulnerabilities from nuclei output")
                return vulnerabilities
        
        return []
        
    except Exception as e:
        logging.error(f"Failed to format nuclei results: {str(e)}")
        return []


def get_scan_statistics(scan_id: str) -> Dict[str, Any]:
    """
    Get comprehensive statistics for a specific scan.
    
    Args:
        scan_id: Unique identifier for the scan
        
    Returns:
        Dict: Scan statistics
    """
    try:
        # This would need to be implemented in db_manager
        # For now, return a basic structure
        return {
            "scan_id": scan_id,
            "total_results": 0,
            "result_types": {},
            "latest_timestamp": None,
            "tools_used": []
        }
        
    except Exception as e:
        logging.error(f"Failed to get statistics for scan {scan_id}: {str(e)}")
        return {"scan_id": scan_id, "error": str(e)} 