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
        enum_scan_id = payload.get("enum_scan_id")
        vuln_scan_id = payload.get("vuln_scan_id")
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
        aggregated_output = aggregate_task_outputs(container_client, domain, enum_scan_id, vuln_scan_id, task)
        
        # Save aggregated output for database storage
        if task == "nuclei":
            output_extension = "json"
            output_blob_name = f"{domain}-{vuln_scan_id}/{task}/out/final_out.json"
        else:
            output_extension = "txt" if task == "subfinder" else "json"
            output_blob_name = f"{domain}-{enum_scan_id}/{task}/out/final_out.{output_extension}"
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
        next_input_path = prepare_next_tool_input(container_client, domain, enum_scan_id, vuln_scan_id, task, aggregated_output)
        if next_input_path:
            logging.info(f"Next tool input prepared: {next_input_path}")
        
      
        
        return output_path
        
    except Exception as e:
        logging.error(f"Failed to aggregate stage results: {str(e)}")
        logging.error(traceback.format_exc())
        
        return {"error": str(e)}
        

def aggregate_task_outputs(container_client, domain: str, enum_scan_id: str, vuln_scan_id: str, task: str) -> any:
    """Aggregate task outputs based on format"""
    if task == "nuclei":
        output_prefix = f"{domain}-{vuln_scan_id}/{task}/out/"
        blobs = container_client.list_blobs(name_starts_with=output_prefix)
        merged_findings = {}  # Use dict for deduplication
        meta = None
        for blob in blobs:
            try:
                blob_client = container_client.get_blob_client(blob.name)
                blob_content = blob_client.download_blob().readall()
                content_text = blob_content.decode('utf-8')
                result_data = json.loads(content_text)
                if meta is None:
                    meta = {
                        "task": result_data.get("task", "nuclei"),
                        "enum_scan_id": enum_scan_id,
                        "vuln_scan_id": vuln_scan_id,
                        "domain": result_data.get("domain", domain),
                        "status": result_data.get("status", "completed"),
                        "data_domain": result_data.get("data", {}).get("domain", domain)
                    }
                if "data" in result_data and "output" in result_data["data"]:
                    output = result_data["data"]["output"]
                    if isinstance(output, list):
                        for finding in output:
                            if isinstance(finding, dict):
                                # Create unique key for deduplication: template_id + host + matched_at + part of request
                                template_id = finding.get("template_id", "")
                                host = finding.get("host", "")
                                matched_at = finding.get("matched_at", "")
                                request = finding.get("request", "")
                                request_part = request[:100] if isinstance(request, str) else ""
                                unique_key = f"{template_id}:{host}:{matched_at}:{request_part}"
                                
                                # Keep the first occurrence of each unique finding
                                if unique_key not in merged_findings:
                                    merged_findings[unique_key] = finding.copy()
                else:
                    logging.warning(f"Nuclei JSON file {blob.name} does not contain expected data.output structure")
            except Exception as e:
                logging.error(f"Failed to read blob {blob.name}: {str(e)}")
                continue
        
        # Convert back to list for final output
        deduplicated_output = list(merged_findings.values())
        logging.info(f"Nuclei aggregation: {len(deduplicated_output)} unique findings after deduplication")
        
        # Compose the final result in the same format as the input files
        result = {
            "task": meta.get("task", "nuclei") if meta else "nuclei",
            "enum_scan_id": meta.get("enum_scan_id", "") if meta else enum_scan_id,
            "vuln_scan_id": meta.get("vuln_scan_id", "") if meta else vuln_scan_id,
            "domain": meta.get("domain", "") if meta else domain,
            "status": meta.get("status", "completed") if meta else "completed",
            "data": {
                "domain": meta.get("data_domain", meta.get("domain", "")) if meta else domain,
                "output": deduplicated_output
            }
        }
        return result
    
    aggregated_data = []
    if task == "subfinder":
        output_prefix = f"{domain}-{enum_scan_id}/{task}/out/"
    else:
        output_prefix = f"{domain}-{enum_scan_id}/{task}/out/"
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
                                "enum_scan_id": enum_scan_id,
                                "vuln_scan_id": vuln_scan_id,
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
                    "enum_scan_id": enum_scan_id,
                    "vuln_scan_id": vuln_scan_id,
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
            "enum_scan_id": meta.get("enum_scan_id", ""),
            "vuln_scan_id": meta.get("vuln_scan_id", ""),
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
            "enum_scan_id": meta.get("enum_scan_id", ""),
            "vuln_scan_id": meta.get("vuln_scan_id", ""),
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
                    "enum_scan_id": enum_scan_id,
                    "vuln_scan_id": vuln_scan_id,
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
            "enum_scan_id": meta.get("enum_scan_id", ""),
            "vuln_scan_id": meta.get("vuln_scan_id", ""),
            "domain": meta.get("domain", ""),
            "status": meta.get("status", "completed"),
            "data": {
                "domain": meta.get("data_domain", meta.get("domain", "")),
                "output": list(merged_hosts.values())
            }
        }
        return result
    
    # For nuclei, aggregate all output lists into one list of dicts, deduplicate by template_id+host+matched_at
    if task == "nuclei":
        merged_findings = {}
        meta = None
        for entry in aggregated_data:
            if not isinstance(entry, dict):
                continue
            if meta is None:
                meta = {
                    "task": "nuclei",
                    "enum_scan_id": enum_scan_id,
                    "vuln_scan_id": vuln_scan_id,
                    "domain": domain,
                    "status": "completed",
                    "data_domain": domain
                }
            # Create a unique key for deduplication: template_id + host + matched_at
            template_id = entry.get("template_id", "")
            host = entry.get("host", "")
            matched_at = entry.get("matched_at", "")
            unique_key = f"{template_id}:{host}:{matched_at}"
            
            # Keep the first occurrence of each unique finding
            if unique_key not in merged_findings:
                merged_findings[unique_key] = entry.copy()
        
        # Compose the final result in the same format as the input files
        result = {
            "task": meta.get("task", "nuclei") if meta else "nuclei",
            "enum_scan_id": meta.get("enum_scan_id", "") if meta else enum_scan_id,
            "vuln_scan_id": meta.get("vuln_scan_id", "") if meta else vuln_scan_id,
            "domain": meta.get("domain", "") if meta else domain,
            "status": meta.get("status", "completed") if meta else "completed",
            "data": {
                "domain": meta.get("data_domain", meta.get("domain", "")) if meta else domain,
                "output": list(merged_findings.values())
            }
        }
        return result
    
    # For other tasks, return the aggregated output
    return aggregated_data

def prepare_next_tool_input(container_client, domain: str, enum_scan_id: str, vuln_scan_id: str, task: str, aggregated_output: any) -> str:
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
    
    if task == "httpx":
        # httpx prepares web servers for nuclei
        # Extract web server URLs for http nuclei
        urls = []
        hosts_in_httpx_out = set()
        
        # Handle both old format (list of results) and new format (dict with data.output)
        httpx_results = []
        if isinstance(aggregated_output, dict) and 'data' in aggregated_output and 'output' in aggregated_output['data']:
            # New format
            httpx_results = aggregated_output['data']['output']
            logging.info(f"Processing httpx results in new format: {len(httpx_results)} results")
        elif isinstance(aggregated_output, list):
            # Old format - direct list of results
            httpx_results = aggregated_output
            logging.info(f"Processing httpx results in old format: {len(httpx_results)} results")
        else:
            logging.error(f"Unexpected httpx aggregated_output format: {type(aggregated_output)}")
            logging.error(f"Content: {aggregated_output}")
            return None
        
        logging.info(f"Processing {len(httpx_results)} httpx results for nuclei input preparation")
        
        for i, httpx_result in enumerate(httpx_results):
            if not isinstance(httpx_result, dict):
                logging.warning(f"httpx result {i} is not a dict: {type(httpx_result)}")
                continue
                
            # Log the structure of the first few results for debugging
            if i < 3:
                logging.info(f"httpx result {i} keys: {list(httpx_result.keys())}")
                logging.info(f"httpx result {i} sample: {httpx_result}")
            
            # Extract URL - try multiple possible field names
            url = None
            if 'url' in httpx_result:
                url = httpx_result['url']
            elif 'input' in httpx_result:
                url = httpx_result['input']
            elif 'host' in httpx_result:
                # Construct URL from host if no URL field
                host = httpx_result['host']
                scheme = httpx_result.get('scheme', 'http')
                port = httpx_result.get('port', '')
                if port and port not in ['80', '443']:
                    url = f"{scheme}://{host}:{port}"
                else:
                    url = f"{scheme}://{host}"
            
            if url:
                urls.append(url)
                if i < 5:  # Only log first 5 URLs to avoid spam
                    logging.info(f"Added URL for nuclei-http: {url}")
            
            # Track hosts for nuclei-network
            if 'host' in httpx_result:
                hosts_in_httpx_out.add(httpx_result['host'])
        
        logging.info(f"Processed {len(httpx_results)} httpx results, found {len(urls)} URLs, {len(hosts_in_httpx_out)} hosts")
        
        urls_text = '\n'.join(urls)
        http_input_blob_name = f"{domain}-{vuln_scan_id}/nuclei-http/in/input.txt"
        http_input_blob_client = container_client.get_blob_client(http_input_blob_name)
        
        if urls_text.strip():
            http_input_blob_client.upload_blob(urls_text, overwrite=True)
            logging.info(f"Successfully uploaded {len(urls)} URLs to nuclei-http input")
        else:
            http_input_blob_client.upload_blob("", overwrite=True)
            logging.warning(f"No URLs found for nuclei-http input - created empty file")
        
        logging.info(f"Prepared {len(urls)} URLs for nuclei-http input: {http_input_blob_name}")
        logging.info(f"URLs content length: {len(urls_text)} characters")
        
        # Log sample URLs for debugging
        if urls:
            sample_urls = urls[:3]  # Show first 3 URLs
            logging.info(f"Sample URLs for nuclei-http: {sample_urls}")
        else:
            logging.warning("No URLs found in httpx results - this might indicate:")
            logging.warning("1. httpx found no web servers")
            logging.warning("2. httpx results don't have 'url' field")
            logging.warning("3. httpx results are empty")
            logging.warning("4. Processing error in input preparation")
        
        # For network nuclei: get httpx input (subdomain:port list) from previous input blob
        httpx_input_blob_name = f"{domain}-{enum_scan_id}/httpx/in/input.txt"
        httpx_input_blob_client = container_client.get_blob_client(httpx_input_blob_name)
        
        try:
            httpx_input_content = httpx_input_blob_client.download_blob().readall().decode('utf-8')
            httpx_input_targets = set(line.strip() for line in httpx_input_content.strip().split('\n') if line.strip())
            
            logging.info(f"Loaded {len(httpx_input_targets)} original httpx input targets")
            logging.info(f"Found {len(hosts_in_httpx_out)} hosts in httpx output")
            
            network_targets = sorted(list(httpx_input_targets - hosts_in_httpx_out))
            
            logging.info(f"Prepared {len(network_targets)} targets for nuclei-network (original - found)")
            
            network_text = '\n'.join(network_targets)
            network_input_blob_name = f"{domain}-{vuln_scan_id}/nuclei-network/in/input.txt"
            network_input_blob_client = container_client.get_blob_client(network_input_blob_name)
            network_input_blob_client.upload_blob(network_text, overwrite=True)
            
            logging.info(f"Prepared nuclei-network input: {network_input_blob_name}")
            logging.info(f"Network content length: {len(network_text)} characters")
            
        except Exception as e:
            logging.error(f"Failed to prepare nuclei-network input: {str(e)}")
            # Create empty file to prevent errors
            network_input_blob_name = f"{domain}-{vuln_scan_id}/nuclei-network/in/input.txt"
            network_input_blob_client = container_client.get_blob_client(network_input_blob_name)
            network_input_blob_client.upload_blob("", overwrite=True)
            logging.warning(f"Created empty nuclei-network input file: {network_input_blob_name}")
        
        return {
            "nuclei_http_input": f"scans/{http_input_blob_name}",
            "nuclei_network_input": f"scans/{network_input_blob_name}"
        }
    
    elif task == "subfinder":
        # subfinder prepares subdomains for dns_resolve
        subdomains_text = '\n'.join(aggregated_output)
        next_input_blob_name = f"{domain}-{enum_scan_id}/{next_task}/in/input.txt"
        next_input_blob_client = container_client.get_blob_client(next_input_blob_name)
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
        
        ips = list(set(ips))  # Remove duplicates
        ips_text = '\n'.join(ips)
        next_input_blob_name = f"{domain}-{enum_scan_id}/{next_task}/in/input.txt"
        next_input_blob_client = container_client.get_blob_client(next_input_blob_name)
        next_input_blob_client.upload_blob(ips_text, overwrite=True)
        logging.info(f"Prepared {len(ips)} unique IPs for port_scan")
        
    elif task == "port_scan":
        # port_scan prepares hosts with open ports for httpx
        # Extract hosts with open ports, but only for subdomains (not IPs)
        hosts = set()

        # 1. Load DNS resolution output to map public IPs to subdomains
        dns_resolve_blob_name = f"{domain}-{enum_scan_id}/dns_resolve/out/final_out.json"
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
        next_input_blob_name = f"{domain}-{enum_scan_id}/{next_task}/in/input.txt"
        next_input_blob_client = container_client.get_blob_client(next_input_blob_name)
        next_input_blob_client.upload_blob(hosts_text, overwrite=True)
        logging.info(f"Prepared {len(hosts)} subdomain:port pairs for httpx")
    
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
