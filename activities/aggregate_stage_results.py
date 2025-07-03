import logging
import json
import os
import datetime
import traceback
import azure.functions as func
import azure.durable_functions as df
from azure.storage.blob import BlobServiceClient
from azure.core.exceptions import ResourceNotFoundError
import asyncio
import ipaddress

app = func.Blueprint()

@app.activity_trigger(input_name="payload")
async def aggregate_stage_results(payload: dict):
    logging.info("=== AGGREGATE STAGE RESULTS ACTIVITY STARTED ===")
    try:
        scan_id = payload.get("scan_id")
        task = payload.get("task")
        domain = payload.get("domain")
        
       
        connection_string = os.environ.get("AzureStorageConnectionString")
        if not connection_string:
            raise ValueError("AzureStorageConnectionString environment variable not set")
        blob_service_client = BlobServiceClient.from_connection_string(connection_string)
        container_name = "scans"
        try:
            container_client = blob_service_client.get_container_client(container_name)
            container_client.get_container_properties()
        except ResourceNotFoundError:
            container_client = blob_service_client.create_container(container_name)
        
        # 1. AGGREGATE OUTPUTS
        aggregated_output = aggregate_task_outputs(container_client, domain, scan_id, task)
        
        # Save aggregated output for database storage
        output_extension = "txt" if task == "subfinder" else "json"
        output_blob_name = f"{domain}-{scan_id}/{task}/out/final_out.{output_extension}"
        output_blob_client = container_client.get_blob_client(output_blob_name)
        
        if output_extension == "txt":
            # For text files, save as plain text
            output_content = '\n'.join(aggregated_output)
            output_blob_client.upload_blob(output_content, overwrite=True)
        else:
            # For JSON files, save as JSON
            output_content = json.dumps(aggregated_output, indent=2, ensure_ascii=False)
            output_blob_client.upload_blob(output_content, overwrite=True)
        
        output_path = f"{container_name}/{output_blob_name}"
        logging.info(f"Task output aggregated and saved to: {output_path}")
        
        # 2. PREPARE NEXT TOOL INPUT (if applicable)
        next_input_path = prepare_next_tool_input(container_client, domain, scan_id, task, aggregated_output)
        if next_input_path:
            logging.info(f"Next tool input prepared: {next_input_path}")
        
      
        
        return output_path
        
    except Exception as e:
        logging.error(f"Failed to aggregate stage results: {str(e)}")
        logging.error(traceback.format_exc())
        
        return {"error": str(e)}
        

def aggregate_task_outputs(container_client, domain: str, scan_id: str, task: str) -> any:
    """Aggregate task outputs based on format"""
    aggregated_data = []
    output_prefix = f"{domain}-{scan_id}/{task}/out/"
    blobs = container_client.list_blobs(name_starts_with=output_prefix)
    
    for blob in blobs:
        try:
            blob_client = container_client.get_blob_client(blob.name)
            blob_content = blob_client.download_blob().readall()
            content_text = blob_content.decode('utf-8')
            
            if task == "subfinder" and blob.name.endswith('.txt'):
                # Handle subfinder text files (one subdomain per line)
                subdomains = process_text_output(content_text)
                aggregated_data.extend(subdomains)
                logging.info(f"Processed subfinder text file {blob.name}: {len(subdomains)} subdomains")
                
            elif blob.name.endswith('.json'):
                # Handle JSON files - extract from blob[data][output]
                result_data = json.loads(content_text)
                if "data" in result_data and "output" in result_data["data"]:
                    output = result_data["data"]["output"]
                    if task == "dns_resolve":
                        # For dns_resolve, output is mapping of subdomain -> A[], CNAME[], status
                        aggregated_data.append(output)
                    elif task == "port_scan":
                        # For port_scan, output is mapping of ip -> [port dicts]
                        aggregated_data.append({
                            "meta": {
                                "task": result_data.get("task"),
                                "scan_id": result_data.get("scan_id"),
                                "domain": result_data.get("domain"),
                                "status": result_data.get("status"),
                                "data_domain": result_data["data"].get("domain")
                            },
                            "output": output
                        })
                    elif task == "httpx":
                        aggregated_data.extend(output)
                    else:
                        # For other tasks, append the output
                        aggregated_data.append(output)
                    logging.info(f"Processed JSON file {blob.name}")
                else:
                    logging.warning(f"JSON file {blob.name} does not contain expected data.output structure")
                    
            else:
                logging.warning(f"Unsupported file format for task {task}: {blob.name}")
                
        except Exception as e:
            logging.error(f"Failed to read blob {blob.name}: {str(e)}")
            continue
    
    # For subfinder, return list of subdomains
    if task == "subfinder":
        return list(dict.fromkeys(aggregated_data))  # Remove duplicates
    
    # For dns_resolve, aggregate into a single output dict mapping subdomain -> DNS records
    if task == "dns_resolve":
        merged_dns_records = {}
        meta = None
        for entry in aggregated_data:
            if not isinstance(entry, dict):
                continue
            if meta is None:
                meta = {
                    "task": "dns_resolve",
                    "scan_id": scan_id,
                    "domain": domain,
                    "status": "completed",
                    "data_domain": domain
                }
            # Merge DNS records by subdomain
            for subdomain, records in entry.items():
                if isinstance(records, dict):
                    if subdomain not in merged_dns_records:
                        merged_dns_records[subdomain] = records.copy()
                    else:
                        # Merge A records
                        existing_a = merged_dns_records[subdomain].get('A', [])
                        new_a = records.get('A', [])
                        merged_dns_records[subdomain]['A'] = list(set(existing_a + new_a))
                        
                        # Merge CNAME records
                        existing_cname = merged_dns_records[subdomain].get('CNAME', [])
                        new_cname = records.get('CNAME', [])
                        merged_dns_records[subdomain]['CNAME'] = list(set(existing_cname + new_cname))
                        
                        # Update status if needed
                        if records.get('status') and merged_dns_records[subdomain].get('status') == 'unknown':
                            merged_dns_records[subdomain]['status'] = records['status']
        
        # Compose the final result in the same format as the input files
        result = {
            "task": meta.get("task", "dns_resolve"),
            "scan_id": meta.get("scan_id", ""),
            "domain": meta.get("domain", ""),
            "status": meta.get("status", "completed"),
            "data": {
                "domain": meta.get("data_domain", meta.get("domain", "")),
                "output": merged_dns_records
            }
        }
        return result
    
    # For port_scan, aggregate into a single output dict in the same format
    if task == "port_scan":
        merged_output = {}
        meta = None
        for entry in aggregated_data:
            if not isinstance(entry, dict) or "output" not in entry:
                continue
            if meta is None:
                meta = entry.get("meta", {})
            for ip, ports in entry["output"].items():
                if ip not in merged_output:
                    merged_output[ip] = []
                # Avoid duplicate port dicts
                for port_dict in ports:
                    if port_dict not in merged_output[ip]:
                        merged_output[ip].append(port_dict)
        # Compose the final result in the same format as the input files
        result = {
            "task": meta.get("task", "port_scan"),
            "scan_id": meta.get("scan_id", ""),
            "domain": meta.get("domain", ""),
            "status": meta.get("status", "completed"),
            "data": {
                "domain": meta.get("data_domain", meta.get("domain", "")),
                "output": merged_output
            }
        }
        return result
    
    # For httpx, aggregate all output lists into one list of dicts, deduplicate by 'host', and handle missing keys gracefully
    if task == "httpx":
        merged_hosts = {}
        meta = None
        for entry in aggregated_data:
            if not isinstance(entry, dict):
                continue
            if meta is None:
                meta = {
                    "task": "httpx",
                    "scan_id": scan_id,
                    "domain": domain,
                    "status": "completed",
                    "data_domain": domain
                }
            if not isinstance(entry, dict):
                continue
            host = entry.get("host")
            if not host:
                continue
            # Merge by host, prefer the first occurrence, but update with any new keys
            if host not in merged_hosts:
                merged_hosts[host] = entry.copy()
            else:
                merged_hosts[host].update({k: v for k, v in entry.items() if k not in merged_hosts[host]})
        # Compose the final result in the same format as the input files
        result = {
            "task": meta.get("task", "httpx"),
            "scan_id": meta.get("scan_id", ""),
            "domain": meta.get("domain", ""),
            "status": meta.get("status", "completed"),
            "data": {
                "domain": meta.get("data_domain", meta.get("domain", "")),
                "output": list(merged_hosts.values())
            }
        }
        return result
    
    # For other tasks, return the aggregated output
    return aggregated_data

def prepare_next_tool_input(container_client, domain: str, scan_id: str, task: str, aggregated_output: any) -> str:
    """Prepare input for the next tool in the pipeline"""
    
    # Define the task pipeline and what each task prepares for the next
    task_pipeline = {
        "subfinder": "dns_resolve",
        "dns_resolve": "port_scan", 
        "port_scan": "httpx",
        "httpx": "nuclei"
    }
    
    next_task = task_pipeline.get(task)
    if not next_task:
        logging.info(f"Task {task} does not prepare input for next task")
        return None
    
    next_input_blob_name = f"{domain}-{scan_id}/{next_task}/in/input.txt"
    next_input_blob_client = container_client.get_blob_client(next_input_blob_name)
    
    if task == "subfinder":
        # subfinder prepares subdomains for dns_resolve
        subdomains_text = '\n'.join(aggregated_output)
        next_input_blob_client.upload_blob(subdomains_text, overwrite=True)
        logging.info(f"Prepared {len(aggregated_output)} subdomains for dns_resolve")
        
    elif task == "dns_resolve":
        # dns_resolve prepares resolved IPs for port_scan
        # Extract IP addresses from DNS results
        ips = []
        
        # Handle new aggregated format
        if isinstance(aggregated_output, dict) and 'data' in aggregated_output and 'output' in aggregated_output['data']:
            # New format: aggregated_output['data']['output'] contains the DNS records
            dns_records = aggregated_output['data']['output']
            for subdomain, records in dns_records.items():
                if isinstance(records, dict) and 'A' in records:
                    ips.extend(records['A'])
        # else:
        #     # Fallback for old format (list of output dicts)
        #     for dns_result in aggregated_output:
        #         if isinstance(dns_result, dict):
        #             for subdomain, records in dns_result.items():
        #                 if isinstance(records, dict) and 'A' in records:
        #                     ips.extend(records['A'])
        
        ips = list(set(ips))  # Remove duplicates
        ips_text = '\n'.join(ips)
        next_input_blob_client.upload_blob(ips_text, overwrite=True)
        logging.info(f"Prepared {len(ips)} unique IPs for port_scan")
        
    elif task == "port_scan":
        # port_scan prepares hosts with open ports for httpx
        # Extract hosts with open ports, but only for subdomains (not IPs)
        hosts = set()

        # 1. Load DNS resolution output to map public IPs to subdomains
        dns_resolve_blob_name = f"{domain}-{scan_id}/dns_resolve/out/final_out.json"
        dns_resolve_blob_client = container_client.get_blob_client(dns_resolve_blob_name)
        try:
            dns_resolve_content = dns_resolve_blob_client.download_blob().readall().decode('utf-8')
            dns_resolve_data = json.loads(dns_resolve_content)
            
            ip_to_subdomains = {}
            if isinstance(dns_resolve_data, dict) and 'data' in dns_resolve_data and 'output' in dns_resolve_data['data']:
                # New aggregated format
                output = dns_resolve_data['data']['output']
                for subdomain, records in output.items():
                    if isinstance(records, dict) and 'A' in records:
                        for ip in records['A']:
                            try:
                                ip_obj = ipaddress.ip_address(ip)
                                if not ip_obj.is_private:
                                    ip_to_subdomains.setdefault(ip, []).append(subdomain)
                            except ValueError:
                                continue
            elif isinstance(dns_resolve_data, list):
                # Old format: list of output dicts
                for output in dns_resolve_data:
                    if isinstance(output, dict):
                        for subdomain, records in output.items():
                            if isinstance(records, dict) and 'A' in records:
                                for ip in records['A']:
                                    try:
                                        ip_obj = ipaddress.ip_address(ip)
                                        if not ip_obj.is_private:
                                            ip_to_subdomains.setdefault(ip, []).append(subdomain)
                                    except ValueError:
                                        continue
        except Exception as e:
            logging.error(f"Failed to load or parse DNS resolution output: {str(e)}")
            ip_to_subdomains = {}

        # 2. Parse port scan output (aggregated_output)
        # aggregated_output is expected to be a dict in the new format
        if isinstance(aggregated_output, dict) and 'data' in aggregated_output and 'output' in aggregated_output['data']:
            portscan_output = aggregated_output['data']['output']
            for ip, ports in portscan_output.items():
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_private:
                        continue  # skip private IPs
                except ValueError:
                    continue
                if ip in ip_to_subdomains:
                    for subdomain in ip_to_subdomains[ip]:
                        for port_dict in ports:
                            port = port_dict.get('port')
                            if port:
                                hosts.add(f"{subdomain}:{port}")
        else:
            logging.warning("Aggregated port scan output is not in expected format for httpx input preparation.")

        hosts_text = '\n'.join(hosts)
        next_input_blob_client.upload_blob(hosts_text, overwrite=True)
        logging.info(f"Prepared {len(hosts)} subdomain:port pairs for httpx")
    
    elif task == "httpx":
        # httpx prepares web servers for nuclei
        # Extract web server URLs
        urls = []
        for httpx_result in aggregated_output:
            if isinstance(httpx_result, dict) and 'url' in httpx_result:
                urls.append(httpx_result['url'])
        
        urls_text = '\n'.join(urls)
        next_input_blob_client.upload_blob(urls_text, overwrite=True)
        logging.info(f"Prepared {len(urls)} URLs for nuclei")
    
    return f"scans/{next_input_blob_name}"

def process_text_output(content: str) -> list:
    """Process text output (one target per line)"""
    try:
        targets = []
        lines = content.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            if line:  # Skip empty lines
                targets.append(line)
        
        logging.info(f"Processed {len(targets)} targets from text output")
        return targets
        
    except Exception as e:
        logging.error(f"Failed to process text output: {str(e)}")
        return []
