import os
import logging
import traceback
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import asyncpg
from config.database_config import DatabaseConfig
import json

import asyncio


class DatabaseManager:
    """
    Database manager for handling all database operations in the security scanning system.
    Works with Azure PostgreSQL and follows the AllSafe ASM schema with optimized batch operations.
    """
    
    def __init__(self):
        self.pool = None
        # Don't call async method in constructor - will be called when needed
    
    async def _initialize_pool(self):
        """Initialize PostgreSQL connection pool."""
        try:
            # Get connection parameters instead of connection string
            connection_params = DatabaseConfig.get_connection_params()
            
            if not all([connection_params['host'], connection_params['user'], connection_params['password']]):
                logging.error("PostgreSQL connection parameters not configured")
                return
            
            self.pool = await asyncpg.create_pool(
                **connection_params,
                min_size=1,
                max_size=10,
                command_timeout=60
            )
            logging.info("PostgreSQL connection pool initialized")
            
          
            
        except Exception as e:
            logging.error(f"Failed to initialize PostgreSQL pool: {str(e)}")
            logging.error(traceback.format_exc())
            
      
    
    async def _get_connection(self):
        """Get a connection from the pool."""
        if not self.pool:
            await self._initialize_pool()
        if not self.pool:
            raise Exception("Failed to initialize database connection pool")
        return await self.pool.acquire()
    
    async def _release_connection(self, conn):
        """Release a connection back to the pool."""
        if self.pool:
            await self.pool.release(conn)
    
    # ==================== SUBFINDER OPERATIONS ====================
    
    async def store_subdomains_from_subfinder(self, domain_id: int, subdomain_names: List[str]) -> Dict[str, Any]:
        """
        Store subdomains discovered by subfinder using batch operations.
        
        Args:
            domain_id: ID of the domain in the domains table
            subdomain_names: List of subdomain names discovered by subfinder
            
        Returns:
            Dict with success status and created/updated subdomain IDs
        """
        try:
            conn = await self._get_connection()
            current_time = datetime.utcnow()
            
            # Batch query to get existing subdomains
            existing_subdomains = await conn.fetch(
                """
                SELECT id, subdomain, first_seen, last_seen 
                FROM subdomains 
                WHERE subdomain = ANY($1) AND domain_id = $2
                """,
                subdomain_names, domain_id
            )
            
            # Create lookup for existing subdomains
            existing_lookup = {row['subdomain']: row for row in existing_subdomains}
            
            # Separate new and existing subdomains
            new_subdomains = []
            existing_to_update = []
            
            for subdomain_name in subdomain_names:
                if subdomain_name in existing_lookup:
                    existing_to_update.append(subdomain_name)
                else:
                    new_subdomains.append(subdomain_name)
            
            created_subdomain_ids = []
            updated_subdomain_ids = []
            
            # Batch insert new subdomains
            if new_subdomains:
                # Prepare batch insert data
                insert_data = [(subdomain, current_time, current_time, domain_id, current_time, current_time) 
                              for subdomain in new_subdomains]
                
                # Use executemany for batch insert
                await conn.executemany(
                    """
                    INSERT INTO subdomains (subdomain, first_seen, last_seen, domain_id, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    """,
                    insert_data
                )
                
                # Get IDs of newly inserted subdomains
                new_subdomain_records = await conn.fetch(
                    """
                    SELECT id FROM subdomains 
                    WHERE subdomain = ANY($1) AND domain_id = $2 AND created_at = $3
                    """,
                    new_subdomains, domain_id, current_time
                )
                created_subdomain_ids = [row['id'] for row in new_subdomain_records]
            
            # Batch update existing subdomains
            if existing_to_update:
                # Prepare batch update data
                update_data = [(current_time, current_time, subdomain, domain_id) 
                              for subdomain in existing_to_update]
                
                # Use executemany for batch update
                await conn.executemany(
                    """
                    UPDATE subdomains 
                    SET last_seen = $1, updated_at = $2
                    WHERE subdomain = $3 AND domain_id = $4
                    """,
                    update_data
                )
                
                # Get IDs of updated subdomains
                updated_subdomain_records = await conn.fetch(
                    """
                    SELECT id FROM subdomains 
                    WHERE subdomain = ANY($1) AND domain_id = $2
                    """,
                    existing_to_update, domain_id
                )
                updated_subdomain_ids = [row['id'] for row in updated_subdomain_records]
            
            await self._release_connection(conn)
            
            result = {
                "success": True,
                "created_count": len(created_subdomain_ids),
                "updated_count": len(updated_subdomain_ids),
                "created_ids": created_subdomain_ids,
                "updated_ids": updated_subdomain_ids
            }
            
            logging.info(f"Stored {len(created_subdomain_ids)} new and updated {len(updated_subdomain_ids)} existing subdomains")
            
         
            return result
            
        except Exception as e:
            logging.error(f"Failed to store subdomains: {str(e)}")
            logging.error(traceback.format_exc())
            
       
            
            return {"success": False, "error": str(e)}
    
    # # ==================== DNS RESOLVE OPERATIONS ====================
    
    # async def store_dns_resolution_results(self, subdomain_id: int, ip_addresses: List[str], 
    #                                      cname_records: Optional[List[str]] = None) -> Dict[str, Any]:
    #     """
    #     Store DNS resolution results using batch operations.
        
    #     Args:
    #         subdomain_id: ID of the subdomain in the subdomains table
    #         ip_addresses: List of resolved IP addresses
    #         cname_records: Optional list of CNAME records
            
    #     Returns:
    #         Dict with success status and created IP/relationship IDs
    #     """
    #     try:
    #         conn = await self._get_connection()
    #         current_time = datetime.utcnow()
            
    #         created_ip_ids = []
    #         created_relationships = []
            
    #         if ip_addresses:
    #             # Batch query to get existing IP addresses
    #             existing_ips = await conn.fetch(
    #                 "SELECT id, ip_address FROM ip_addresses WHERE ip_address = ANY($1)",
    #                 ip_addresses
    #             )
                
    #             # Create lookup for existing IPs
    #             existing_ip_lookup = {row['ip_address']: row['id'] for row in existing_ips}
                
    #             # Separate new and existing IPs
    #             new_ips = [ip for ip in ip_addresses if ip not in existing_ip_lookup]
    #             existing_ip_ids = [existing_ip_lookup[ip] for ip in ip_addresses if ip in existing_ip_lookup]
                
    #             # Batch insert new IP addresses
    #             if new_ips:
    #                 # Prepare batch insert data
    #                 insert_data = [(ip, current_time, current_time) for ip in new_ips]
                    
    #                 # Use executemany for batch insert
    #                 await conn.executemany(
    #                     """
    #                     INSERT INTO ip_addresses (ip_address, created_at, updated_at)
    #                     VALUES ($1, $2, $3)
    #                     """,
    #                     insert_data
    #                 )
                    
    #                 # Get IDs of newly inserted IPs
    #                 new_ip_records = await conn.fetch(
    #                     "SELECT id FROM ip_addresses WHERE ip_address = ANY($1) AND created_at = $2",
    #                     new_ips, current_time
    #                 )
    #                 new_ip_ids = [row['id'] for row in new_ip_records]
    #                 created_ip_ids.extend(new_ip_ids)
                
    #             # Combine all IP IDs
    #             all_ip_ids = existing_ip_ids + created_ip_ids
                
    #             # Batch query to get existing subdomain-IP relationships
    #             existing_relationships = await conn.fetch(
    #                 """
    #                 SELECT ip_address_id FROM subdomain_ips 
    #                 WHERE subdomain_id = $1 AND ip_address_id = ANY($2)
    #                 """,
    #                 subdomain_id, all_ip_ids
    #             )
                
    #             existing_relationship_ip_ids = {row['ip_address_id'] for row in existing_relationships}
                
    #             # Find IPs that need new relationships
    #             new_relationship_ip_ids = [ip_id for ip_id in all_ip_ids if ip_id not in existing_relationship_ip_ids]
                
    #             # Batch insert new subdomain-IP relationships
    #             if new_relationship_ip_ids:
    #                 # Prepare batch insert data
    #                 relationship_data = [(subdomain_id, ip_id, current_time, current_time, current_time) 
    #                                    for ip_id in new_relationship_ip_ids]
                    
    #                 # Use executemany for batch insert
    #                 await conn.executemany(
    #                     """
    #                     INSERT INTO subdomain_ips (subdomain_id, ip_address_id, resolved_on, created_at, updated_at)
    #                     VALUES ($1, $2, $3, $4, $5)
    #                     """,
    #                     relationship_data
    #                 )
                    
    #                 # Get IDs of newly created relationships
    #                 new_relationship_records = await conn.fetch(
    #                     """
    #                     SELECT id FROM subdomain_ips 
    #                     WHERE subdomain_id = $1 AND ip_address_id = ANY($2) AND created_at = $3
    #                     """,
    #                     subdomain_id, new_relationship_ip_ids, current_time
    #                 )
    #                 created_relationships = [row['id'] for row in new_relationship_records]
            
    #         # Batch insert CNAME records if provided
    #         if cname_records:
    #             # Prepare batch insert data
    #             cname_data = [(cname, subdomain_id, current_time, current_time) for cname in cname_records]
                
    #             # Use executemany for batch insert
    #             await conn.executemany(
    #                 """
    #                 INSERT INTO dns_records (cname_record, subdomain_id, created_at, updated_at)
    #                 VALUES ($1, $2, $3, $4)
    #                 """,
    #                 cname_data
    #             )
            
    #         await self._release_connection(conn)
            
    #         result = {
    #             "success": True,
    #             "created_ip_count": len(created_ip_ids),
    #             "created_relationship_count": len(created_relationships),
    #             "created_ip_ids": created_ip_ids,
    #             "created_relationship_ids": created_relationships
    #         }
            
    #         logging.info(f"Stored DNS resolution results: {len(created_ip_ids)} new IPs, {len(created_relationships)} new relationships")
    #         return result
            
    #     except Exception as e:
    #         logging.error(f"Failed to store DNS resolution results: {str(e)}")
    #         logging.error(traceback.format_exc())
    #         return {"success": False, "error": str(e)}
    
    async def store_dns_resolve_results_batch(self, domain_id: int, dns_results: Dict[str, Dict[str, any]]) -> Dict[str, Any]:
        """
        Store dns_resolve results for all subdomains in a single batch operation.
        
        Args:
            domain_id: ID of the domain in the domains table
            dns_results: Dict mapping subdomain to its resolution info
                       Format: {"subdomain": {"A": ["ip1", "ip2"], "CNAME": ["cname1"], "status": "resolved"}}
            
        Returns:
            Dict with success status and created records
        """
        try:
            conn = await self._get_connection()
            current_time = datetime.utcnow()
            
            total_created_ips = 0
            total_created_relationships = 0
            total_created_cnames = 0
            total_updated_subdomains = 0
            
            # Get all subdomain names from the DNS results
            subdomain_names = list(dns_results.keys())
            
            if not subdomain_names:
                await self._release_connection(conn)
                
              
                
                return {"success": True, "message": "No subdomains found in DNS results"}
            
            # Batch query to get existing subdomains for this domain
            existing_subdomains = await conn.fetch(
                """
                SELECT id, subdomain FROM subdomains 
                WHERE subdomain = ANY($1) AND domain_id = $2
                """,
                subdomain_names, domain_id
            )
            
            # Create lookup for existing subdomains
            existing_subdomain_lookup = {row['subdomain']: row['id'] for row in existing_subdomains}
            
            # Collect all unique IP addresses and CNAME records
            all_ip_addresses = set()
            all_cname_records = []
            
            for subdomain, resolution_info in dns_results.items():
                # Collect A records (IP addresses)
                a_records = resolution_info.get('A', [])
                if isinstance(a_records, list):
                    all_ip_addresses.update(a_records)
                
                # Collect CNAME records
                cname_records = resolution_info.get('CNAME', [])
                if isinstance(cname_records, list):
                    for cname in cname_records:
                        all_cname_records.append((subdomain, cname))
            
            # Batch query to get existing IP addresses
            existing_ips = await conn.fetch(
                "SELECT id, ip_address FROM ip_addresses WHERE ip_address = ANY($1)",
                list(all_ip_addresses)
            )
            
            # Create lookup for existing IPs
            existing_ip_lookup = {row['ip_address']: row['id'] for row in existing_ips}
            
            # Separate new and existing IPs
            new_ips = [ip for ip in all_ip_addresses if ip not in existing_ip_lookup]
            existing_ip_ids = [existing_ip_lookup[ip] for ip in all_ip_addresses if ip in existing_ip_lookup]
            
            # Batch insert new IP addresses
            if new_ips:
                # Prepare batch insert data
                insert_data = [(ip, current_time, current_time) for ip in new_ips]
                
                # Use executemany for batch insert
                await conn.executemany(
                    """
                    INSERT INTO ip_addresses (ip_address, created_at, updated_at)
                    VALUES ($1, $2, $3)
                    """,
                    insert_data
                )
                
                # Get IDs of newly inserted IPs
                new_ip_records = await conn.fetch(
                    "SELECT id FROM ip_addresses WHERE ip_address = ANY($1) AND created_at = $2",
                    new_ips, current_time
                )
                new_ip_ids = [row['id'] for row in new_ip_records]
                total_created_ips = len(new_ip_ids)
                
                # Add new IP IDs to lookup
                for ip_address, ip_id in zip(new_ips, new_ip_ids):
                    existing_ip_lookup[ip_address] = ip_id
            
            # Process each subdomain's DNS results
            for subdomain, resolution_info in dns_results.items():
                subdomain_id = existing_subdomain_lookup.get(subdomain)
                
                if not subdomain_id:
                    logging.warning(f"Subdomain {subdomain} not found in database, skipping DNS results")
                    continue
                
                # Get DNS status
                dns_status = resolution_info.get('status', 'unknown')
                
                # Get IP addresses for this subdomain
                a_records = resolution_info.get('A', [])
                if isinstance(a_records, list):
                    ip_ids_for_subdomain = [existing_ip_lookup[ip] for ip in a_records if ip in existing_ip_lookup]
                    
                    if ip_ids_for_subdomain:
                        # Batch query to get existing subdomain-IP relationships
                        existing_relationships = await conn.fetch(
                            """
                            SELECT ip_address_id FROM subdomain_ips 
                            WHERE subdomain_id = $1 AND ip_address_id = ANY($2)
                            """,
                            subdomain_id, ip_ids_for_subdomain
                        )
                        
                        existing_relationship_ip_ids = {row['ip_address_id'] for row in existing_relationships}
                        
                        # Find IPs that need new relationships
                        new_relationship_ip_ids = [ip_id for ip_id in ip_ids_for_subdomain if ip_id not in existing_relationship_ip_ids]
                        
                        # Batch insert new subdomain-IP relationships
                        if new_relationship_ip_ids:
                            # Prepare batch insert data
                            relationship_data = [(subdomain_id, ip_id, current_time, current_time, current_time) 
                                               for ip_id in new_relationship_ip_ids]
                            
                            # Use executemany for batch insert
                            await conn.executemany(
                                """
                                INSERT INTO subdomain_ips (subdomain_id, ip_address_id, resolved_on, created_at, updated_at)
                                VALUES ($1, $2, $3, $4, $5)
                                """,
                                relationship_data
                            )
                            
                            total_created_relationships += len(new_relationship_ip_ids)
                
                # Update subdomain's last_seen timestamp and DNS status
                await conn.execute(
                    """
                    UPDATE subdomains 
                    SET last_seen = $1, updated_at = $2, dns_status = $3
                    WHERE id = $4
                    """,
                    current_time, current_time, dns_status, subdomain_id
                )
                total_updated_subdomains += 1
            
            # Batch insert CNAME records
            if all_cname_records:
                # Get subdomain IDs for CNAME records
                cname_data = []
                for subdomain, cname in all_cname_records:
                    subdomain_id = existing_subdomain_lookup.get(subdomain)
                    if subdomain_id:
                        cname_data.append((cname, subdomain_id, current_time, current_time))
                
                if cname_data:
                    # Extract cname records and subdomain IDs for the query
                    cname_records = [cname for cname, subdomain_id, _, _ in cname_data]
                    subdomain_ids = [subdomain_id for _, subdomain_id, _, _ in cname_data]
                    
                    # Check for existing CNAME records to avoid duplicates
                    existing_cname_records = await conn.fetch(
                        """
                        SELECT cname_record, subdomain_id FROM dns_records 
                        WHERE cname_record = ANY($1) AND subdomain_id = ANY($2)
                        """,
                        cname_records, subdomain_ids
                    )
                    
                    # Create set of existing CNAME records
                    existing_cname_set = {(row['cname_record'], row['subdomain_id']) for row in existing_cname_records}
                    
                    # Filter out existing CNAME records
                    new_cname_data = [
                        (cname, subdomain_id, created_at, updated_at) 
                        for cname, subdomain_id, created_at, updated_at in cname_data
                        if (cname, subdomain_id) not in existing_cname_set
                    ]
                    
                    if new_cname_data:
                        # Use executemany for batch insert (without ON CONFLICT)
                        await conn.executemany(
                            """
                            INSERT INTO dns_records (cname_record, subdomain_id, created_at, updated_at)
                            VALUES ($1, $2, $3, $4)
                            """,
                            new_cname_data
                        )
                        total_created_cnames = len(new_cname_data)
                    else:
                        total_created_cnames = 0
            
            await self._release_connection(conn)
            
            result = {
                "success": True,
                "created_ips": total_created_ips,
                "created_relationships": total_created_relationships,
                "created_cnames": total_created_cnames,
                "updated_subdomains": total_updated_subdomains,
                "total_subdomains": len(subdomain_names)
            }
            
            logging.info(f"Stored DNS resolve results: {total_created_ips} new IPs, {total_created_relationships} new relationships, {total_created_cnames} CNAMEs, {total_updated_subdomains} updated subdomains")
            
        
            
            return result
            
        except Exception as e:
            logging.error(f"Failed to store DNS resolve results: {str(e)}")
            logging.error(traceback.format_exc())
            
           
            
            return {"success": False, "error": str(e)}
    
    # ==================== PORT SCAN OPERATIONS ====================
    
    async def store_port_scan_results_batch(self, domain_id: int, port_scan_results: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Store port scan results for all IPs in a single batch operation.
        
        Args:
            domain_id: ID of the domain in the domains table
            port_scan_results: Dict mapping IP address to list of port dictionaries
                             Format: {"192.168.1.1": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]}
            
        Returns:
            Dict with success status and created records
        """
        try:
            conn = await self._get_connection()
            current_time = datetime.utcnow()
            
            total_created_ports = 0
            total_updated_ips = 0
            
            # Get all unique IP addresses from the port scan results
            all_ip_addresses = list(port_scan_results.keys())
            
            if not all_ip_addresses:
                await self._release_connection(conn)
                return {"success": True, "message": "No IP addresses found in port scan results"}
            
            # Batch query to get existing IP addresses for this domain
            # We need to get IPs that are associated with subdomains of this domain
            existing_ips = await conn.fetch(
                """
                SELECT DISTINCT ip.id, ip.ip_address 
                FROM ip_addresses ip
                JOIN subdomain_ips si ON ip.id = si.ip_address_id
                JOIN subdomains s ON si.subdomain_id = s.id
                WHERE ip.ip_address = ANY($1) AND s.domain_id = $2
                """,
                all_ip_addresses, domain_id
            )
            
            # Create lookup for existing IPs
            existing_ip_lookup = {row['ip_address']: row['id'] for row in existing_ips}
            
            # Process each IP's port scan results
            for ip_address, port_list in port_scan_results.items():
                ip_id = existing_ip_lookup.get(ip_address)
                
                if not ip_id:
                    logging.warning(f"IP address {ip_address} not found in database for domain {domain_id}, skipping port scan results")
                    continue
                
                # Extract port numbers from port dictionaries
                port_numbers = []
                for port_dict in port_list:
                    if isinstance(port_dict, dict) and 'port' in port_dict:
                        try:
                            port_number = int(port_dict['port'])
                            port_numbers.append(port_number)
                        except (ValueError, TypeError):
                            continue
                
                if not port_numbers:
                    continue
                
                # Batch query to get existing ports for this IP
                existing_ports = await conn.fetch(
                    """
                    SELECT port_number FROM open_ports 
                    WHERE port_number = ANY($1) AND ip_address_id = $2
                    """,
                    port_numbers, ip_id
                )
                
                existing_port_numbers = {row['port_number'] for row in existing_ports}
                
                # Find new ports to insert
                new_ports = [port for port in port_numbers if port not in existing_port_numbers]
                
                if new_ports:
                    # Determine which ports are web ports based on common web services
                    web_ports = {80, 443, 8080, 8443, 3000, 8000, 9000}
                    
                    # Also check if any port has web-related service names
                    web_services = {'http', 'https', 'http-proxy', 'http-alt', 'web'}
                    for port_dict in port_list:
                        if isinstance(port_dict, dict):
                            service = port_dict.get('service', '').lower()
                            if any(web_service in service for web_service in web_services):
                                web_ports.add(port_dict.get('port'))
                    
                    # Prepare batch insert data
                    insert_data = [(port, port in web_ports, ip_id, current_time, current_time) 
                                  for port in new_ports]
                    
                    # Use executemany for batch insert
                    await conn.executemany(
                        """
                        INSERT INTO open_ports (port_number, is_web, ip_address_id, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5)
                        """,
                        insert_data
                    )
                    
                    total_created_ports += len(new_ports)
                
                total_updated_ips += 1
            
            await self._release_connection(conn)
            
            result = {
                "success": True,
                "created_ports": total_created_ports,
                "updated_ips": total_updated_ips,
                "total_ips": len(all_ip_addresses)
            }
            
            logging.info(f"Stored port scan results: {total_created_ports} new ports across {total_updated_ips} IPs")
            return result
            
        except Exception as e:
            logging.error(f"Failed to store port scan results: {str(e)}")
            logging.error(traceback.format_exc())
            return {"success": False, "error": str(e)}
    
    async def store_port_scan_results(self, ip_address: str, open_ports: List[int], 
                                    web_ports: Optional[List[int]] = None) -> Dict[str, Any]:
        """
        Store port scan results using batch operations.
        
        Args:
            ip_address: The IP address that was scanned
            open_ports: List of open port numbers
            web_ports: Optional list of ports that serve web content
            
        Returns:
            Dict with success status and created port IDs
        """
        try:
            conn = await self._get_connection()
            current_time = datetime.utcnow()
            
            # Get IP address ID
            ip_record = await conn.fetchrow(
                "SELECT id FROM ip_addresses WHERE ip_address = $1",
                ip_address
            )
            
            if not ip_record:
                await self._release_connection(conn)
                return {"success": False, "error": f"IP address {ip_address} not found in database"}
            
            ip_id = ip_record['id']
            
            # Batch query to get existing ports for this IP
            existing_ports = await conn.fetch(
                """
                SELECT port_number FROM open_ports 
                WHERE port_number = ANY($1) AND ip_address_id = $2
                """,
                open_ports, ip_id
            )
            
            existing_port_numbers = {row['port_number'] for row in existing_ports}
            
            # Find new ports to insert
            new_ports = [port for port in open_ports if port not in existing_port_numbers]
            
            created_port_ids = []
            
            # Batch insert new ports
            if new_ports:
                # Determine which ports are web ports
                web_port_set = set(web_ports or [80, 443, 8080, 8443])
                
                # Prepare batch insert data
                insert_data = [(port, port in web_port_set, ip_id, current_time, current_time) 
                              for port in new_ports]
                
                # Use executemany for batch insert
                await conn.executemany(
                    """
                    INSERT INTO open_ports (port_number, is_web, ip_address_id, created_at, updated_at)
                    VALUES ($1, $2, $3, $4, $5)
                    """,
                    insert_data
                )
                
                # Get IDs of newly inserted ports
                new_port_records = await conn.fetch(
                    """
                    SELECT id FROM open_ports 
                    WHERE port_number = ANY($1) AND ip_address_id = $2 AND created_at = $3
                    """,
                    new_ports, ip_id, current_time
                )
                created_port_ids = [row['id'] for row in new_port_records]
            
            await self._release_connection(conn)
            
            result = {
                "success": True,
                "created_port_count": len(created_port_ids),
                "created_port_ids": created_port_ids
            }
            
            logging.info(f"Stored {len(created_port_ids)} open ports for IP {ip_address}")
            return result
            
        except Exception as e:
            logging.error(f"Failed to store port scan results: {str(e)}")
            logging.error(traceback.format_exc())
            return {"success": False, "error": str(e)}
    
    # ==================== HTTPX OPERATIONS ====================
    
    async def store_httpx_results(self, subdomain_id: int, webserver_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Store httpx results using batch operations.
        
        Args:
            subdomain_id: ID of the subdomain in the subdomains table
            webserver_data: List of webserver data from httpx
            
        Returns:
            Dict with success status and created webserver/technology IDs
        """
        try:
            conn = await self._get_connection()
            current_time = datetime.utcnow()
            
            created_webserver_ids = []
            created_technology_ids = []
            created_relationships = []
            
            # Extract all unique technologies from all webservers
            all_technologies = []
            for webserver in webserver_data:
                technologies = webserver.get('technologies', [])
                for tech in technologies:
                    tech_name = tech.get('name', '')
                    tech_version = tech.get('version', '')
                    if tech_name:
                        all_technologies.append((tech_name, tech_version))
            
            # Remove duplicates while preserving order
            unique_technologies = []
            seen = set()
            for tech_name, tech_version in all_technologies:
                tech_key = (tech_name, tech_version)
                if tech_key not in seen:
                    seen.add(tech_key)
                    unique_technologies.append((tech_name, tech_version))
            
            # Batch query to get existing technologies
            if unique_technologies:
                tech_names, tech_versions = zip(*unique_technologies)
                existing_techs = await conn.fetch(
                    """
                    SELECT id, name, version FROM technologies 
                    WHERE (name, version) = ANY($1)
                    """,
                    list(zip(tech_names, tech_versions))
                )
                
                # Create lookup for existing technologies
                existing_tech_lookup = {(row['name'], row['version']): row['id'] for row in existing_techs}
                
                # Separate new and existing technologies
                new_techs = []
                for tech_name, tech_version in unique_technologies:
                    if (tech_name, tech_version) not in existing_tech_lookup:
                        new_techs.append((tech_name, tech_version))
                
                # Batch insert new technologies
                if new_techs:
                    # Prepare batch insert data
                    tech_insert_data = [(name, version, current_time, current_time) for name, version in new_techs]
                    
                    # Use executemany for batch insert
                    await conn.executemany(
                        """
                        INSERT INTO technologies (name, version, created_at, updated_at)
                        VALUES ($1, $2, $3, $4)
                        """,
                        tech_insert_data
                    )
                    
                    # Get IDs of newly inserted technologies
                    new_tech_records = await conn.fetch(
                        """
                        SELECT id, name, version FROM technologies 
                        WHERE (name, version) = ANY($1) AND created_at = $2
                        """,
                        new_techs, current_time
                    )
                    
                    # Add new tech IDs to lookup
                    for row in new_tech_records:
                        existing_tech_lookup[(row['name'], row['version'])] = row['id']
                        created_technology_ids.append(row['id'])
            
            # Process webservers
            for webserver in webserver_data:
                # Insert webserver record
                webserver_id = await conn.fetchval(
                    """
                    INSERT INTO webservers (
                        port_number, name, title, status_code, content_length, url, subdomain_id, created_at, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING id
                    """,
                    webserver.get('port', 80),
                    webserver.get('webserver', ''),
                    webserver.get('title', ''),
                    webserver.get('status_code'),
                    webserver.get('content_length'),
                    webserver.get('url', ''),
                    subdomain_id,
                    current_time,
                    current_time
                )
                created_webserver_ids.append(webserver_id)
                
                # Process technologies for this webserver
                technologies = webserver.get('technologies', [])
                for tech in technologies:
                    tech_name = tech.get('name', '')
                    tech_version = tech.get('version', '')
                    
                    if tech_name and (tech_name, tech_version) in existing_tech_lookup:
                        tech_id = existing_tech_lookup[(tech_name, tech_version)]
                        
                        # Check if relationship already exists
                        existing_relationship = await conn.fetchrow(
                            """
                            SELECT id FROM webservers_technologies 
                            WHERE webserver_id = $1 AND technology_id = $2
                            """,
                            webserver_id, tech_id
                        )
                        
                        if not existing_relationship:
                            # Create webserver-technology relationship
                            relationship_id = await conn.fetchval(
                                """
                                INSERT INTO webservers_technologies (webserver_id, technology_id, created_at, updated_at)
                                VALUES ($1, $2, $3, $4)
                                RETURNING id
                                """,
                                webserver_id, tech_id, current_time, current_time
                            )
                            created_relationships.append(relationship_id)
            
            await self._release_connection(conn)
            
            result = {
                "success": True,
                "created_webserver_count": len(created_webserver_ids),
                "created_technology_count": len(created_technology_ids),
                "created_relationship_count": len(created_relationships),
                "created_webserver_ids": created_webserver_ids,
                "created_technology_ids": created_technology_ids,
                "created_relationship_ids": created_relationships
            }
            
            logging.info(f"Stored httpx results: {len(created_webserver_ids)} webservers, {len(created_technology_ids)} technologies")
            return result
            
        except Exception as e:
            logging.error(f"Failed to store httpx results: {str(e)}")
            logging.error(traceback.format_exc())
            return {"success": False, "error": str(e)}
    
    # ==================== BATCH UTILITY METHODS ====================
    
    async def get_domain_ids_batch(self, domain_names: List[str]) -> Dict[str, int]:
        """
        Get domain IDs for multiple domains in a single query.
        
        Args:
            domain_names: List of domain names
            
        Returns:
            Dict mapping domain names to their IDs
        """
        try:
            conn = await self._get_connection()
            
            domain_records = await conn.fetch(
                """
                SELECT id, domain FROM domains 
                WHERE domain = ANY($1) 
                """,
                domain_names
            )
            
            await self._release_connection(conn)
            
            return {row['domain']: row['id'] for row in domain_records}
            
        except Exception as e:
            logging.error(f"Failed to get domain IDs batch: {str(e)}")
            return {}
    
    async def get_subdomain_ids_batch(self, subdomain_names: List[str], domain_id: int) -> Dict[str, int]:
        """
        Get subdomain IDs for multiple subdomains in a single query.
        
        Args:
            subdomain_names: List of subdomain names
            domain_id: The domain ID
            
        Returns:
            Dict mapping subdomain names to their IDs
        """
        try:
            conn = await self._get_connection()
            
            subdomain_records = await conn.fetch(
                """
                SELECT id, subdomain FROM subdomains 
                WHERE subdomain = ANY($1) AND domain_id = $2
                """,
                subdomain_names, domain_id
            )
            
            await self._release_connection(conn)
            
            return {row['subdomain']: row['id'] for row in subdomain_records}
            
        except Exception as e:
            logging.error(f"Failed to get subdomain IDs batch: {str(e)}")
            return {}
    
    async def get_ip_address_ids_batch(self, ip_addresses: List[str]) -> Dict[str, int]:
        """
        Get IP address IDs for multiple IPs in a single query.
        
        Args:
            ip_addresses: List of IP addresses
            
        Returns:
            Dict mapping IP addresses to their IDs
        """
        try:
            conn = await self._get_connection()
            
            ip_records = await conn.fetch(
                "SELECT id, ip_address FROM ip_addresses WHERE ip_address = ANY($1)",
                ip_addresses
            )
            
            await self._release_connection(conn)
            
            return {row['ip_address']: row['id'] for row in ip_records}
            
        except Exception as e:
            logging.error(f"Failed to get IP address IDs batch: {str(e)}")
            return {}
    
    # ==================== LEGACY SINGLE QUERY METHODS ====================
    
    async def get_domain_id(self, domain_name: str) -> Optional[int]:
        """Get domain ID by domain name."""
        domain_ids = await self.get_domain_ids_batch([domain_name])
        return domain_ids.get(domain_name)
    
    async def get_domain_id_by_user(self, domain_name: str, user_id: int) -> Optional[int]:
        """Get domain ID by domain name and user ID."""
        try:
            conn = await self._get_connection()
            
            domain_record = await conn.fetchrow(
                """
                SELECT id FROM domains 
                WHERE domain = $1 AND user_id = $2
                """,
                domain_name, user_id
            )
            
            await self._release_connection(conn)
            
            return domain_record['id'] if domain_record else None
            
        except Exception as e:
            logging.error(f"Failed to get domain ID by user: {str(e)}")
            return None
    
    async def get_subdomain_id(self, subdomain_name: str, domain_id: int) -> Optional[int]:
        """Get subdomain ID by subdomain name and domain ID."""
        subdomain_ids = await self.get_subdomain_ids_batch([subdomain_name], domain_id)
        return subdomain_ids.get(subdomain_name)
    
    async def get_ip_address_id(self, ip_address: str) -> Optional[int]:
        """Get IP address ID by IP address."""
        ip_ids = await self.get_ip_address_ids_batch([ip_address])
        return ip_ids.get(ip_address)
    
    async def close(self):
        """Close the database connection pool."""
        if self.pool:
            await self.pool.close()

    async def store_enumeration_scan_results(
        self,
        enumeration_scan_id: int,
        httpx_output: list,
        dns_resolve_output: dict
    ) -> dict:
        """
        Store aggregated scan results in enumeration_scan_results table.
        """
        try:
            conn = await self._get_connection()
            current_time = datetime.utcnow()

            # Build subdomain -> IPs and CNAMEs mapping from dns_resolve_output
            sub_to_ips = {}
            sub_to_cnames = {}
            for sub, records in dns_resolve_output.items():
                sub_to_ips[sub] = records.get("A", [])
                sub_to_cnames[sub] = records.get("CNAME", [])

            insert_data = []
            for entry in httpx_output:
                host = entry.get("host", "")
                if ":" in host:
                    subdomain, port = host.rsplit(":", 1)
                    try:
                        port = int(port)
                    except Exception:
                        port = None
                else:
                    subdomain = host
                    port = None

                # Compose URL
                url = entry.get("url")
                if not url:
                    scheme = "https" if port == 443 or port == 8443 else "http"
                    url = f"{scheme}://{host}"

                # Compose technologies as JSONB
                techs = entry.get("technologies", [])
                if isinstance(techs, list):
                    techs_json = json.dumps(techs)
                else:
                    techs_json = json.dumps([techs])

                # Compose IPs and CNAMEs as JSONB
                ips_json = json.dumps(sub_to_ips.get(subdomain, []))
                cnames_json = json.dumps(sub_to_cnames.get(subdomain, []))

                insert_data.append((
                    enumeration_scan_id,
                    subdomain,
                    entry.get("web_server"),
                    entry.get("title"),
                    techs_json,
                    ips_json,
                    entry.get("status_code"),
                    port,
                    entry.get("asn"),
                    entry.get("content_length"),
                    cnames_json,
                    url,
                    current_time,
                    current_time
                ))

            await conn.executemany(
                """
                INSERT INTO enumeration_scan_results (
                    enumeration_scan_id, name, webserver, title, technologies, ip, status_code, port, asn, content_length, cname, url, created_at, updated_at
                ) VALUES (
                    $1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8, $9, $10, $11::jsonb, $12, $13, $14
                )
                """,
                insert_data
            )

            await self._release_connection(conn)
            return {"success": True, "inserted": len(insert_data)}
        except Exception as e:
            logging.error(f"Failed to store enumeration scan results: {str(e)}")
            logging.error(traceback.format_exc())
            return {"success": False, "error": str(e)}

    async def update_enumeration_scan_status(self, enumeration_scan_id: int, status: str) -> dict:
        """
        Update the status of an enumeration scan.
        """
        try:
            conn = await self._get_connection()
            await conn.execute(
                """
                UPDATE enumeration_scans
                SET status = $1, updated_at = NOW()
                WHERE id = $2
                """,
                status, enumeration_scan_id
            )
            await self._release_connection(conn)
            return {"success": True}
        except Exception as e:
            logging.error(f"Failed to update enumeration scan status: {str(e)}")
            logging.error(traceback.format_exc())
            return {"success": False, "error": str(e)}

    async def update_enumeration_scan_summary(self, enumeration_scan_id: int, total_assets: int) -> dict:
        """
        Update total_assets and scan_time_elapsed for an enumeration scan.
        """
        try:
            conn = await self._get_connection()
            # Calculate scan_time_elapsed as the difference between now and created_at
            await conn.execute(
                """
                UPDATE enumeration_scans
                SET total_assets = $1,
                    scan_time_elapsed = EXTRACT(EPOCH FROM (NOW() - created_at))
                WHERE id = $2
                """,
                total_assets, enumeration_scan_id
            )
            await self._release_connection(conn)
            return {"success": True}
        except Exception as e:
            logging.error(f"Failed to update enumeration scan summary: {str(e)}")
            logging.error(traceback.format_exc())
            return {"success": False, "error": str(e)} 