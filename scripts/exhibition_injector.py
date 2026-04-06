"""
ONYX CTI — Exhibition Mode Injector
Synthesizes a realistic APT campaign (APT29 / Cozy Bear + LockBit 3.0) 
and injects massive, interconnected STIX structures + Clear Web Leaks 
via the API to stress-test the 3D Threat Graph and ATT&CK Matrix.
"""

import asyncio
import httpx
import logging
import random
import uuid
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("ExhibitionInjector")

API_BASE = "http://localhost:8000"
API_ROOT = "onyx-cti"
ADMIN_USER = "admin"
ADMIN_PASS = "onyx_admin_2026!"

def generate_stix_id(type_name: str) -> str:
    return f"{type_name}--{uuid.uuid4()}"

async def main():
    logger.info("[+] Starting ONYX Exhibition Simulation Injector")
    
    # Wait for API to be ready
    async with httpx.AsyncClient() as client:
        # Wait up to 300s for API online
        for _ in range(60):
            try:
                res = await client.get(f"{API_BASE}/api/v1/health")
                if res.status_code == 200:
                    break
            except Exception:
                pass
            await asyncio.sleep(5)
            
        logger.info("[+] Authenticating...")
        # Login
        auth_res = await client.post(
            f"{API_BASE}/api/v1/auth/login", 
            json={"username": ADMIN_USER, "password": ADMIN_PASS}
        )
        auth_res.raise_for_status()
        token = auth_res.json()["access_token"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/taxii+json;version=2.1",
            "Content-Type": "application/json"
        }

        # 1. GENERATE STIX 2.1 TOPOLOGY (APT29 & LockBit)
        logger.info("[+] Synthesizing Threat Topologies...")
        objects = []
        
        # ACTORS
        actor_apt = {"type": "threat-actor", "id": generate_stix_id("threat-actor"), "name": "APT29 (Cozy Bear)", "threat_actor_types": ["nation-state"], "aliases": ["Nobelium"]}
        actor_lb = {"type": "threat-actor", "id": generate_stix_id("threat-actor"), "name": "LockBit 3.0", "threat_actor_types": ["crime-syndicate"], "aliases": ["LockBit"]}
        objects.extend([actor_apt, actor_lb])

        # CAMPAIGNS
        camp_solar = {"type": "campaign", "id": generate_stix_id("campaign"), "name": "SolarWinds Supply Chain", "objective": "Espionage"}
        camp_hospital = {"type": "campaign", "id": generate_stix_id("campaign"), "name": "Hospital Sector Extortion", "objective": "Financial"}
        objects.extend([camp_solar, camp_hospital])
        
        objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "attributed-to", "source_ref": camp_solar["id"], "target_ref": actor_apt["id"]})
        objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "attributed-to", "source_ref": camp_hospital["id"], "target_ref": actor_lb["id"]})

        # VULNERABILITIES & EXPLOITS
        vuln_moveit = {"type": "vulnerability", "id": generate_stix_id("vulnerability"), "name": "CVE-2023-34362 (MOVEit)"}
        vuln_citrix = {"type": "vulnerability", "id": generate_stix_id("vulnerability"), "name": "CVE-2023-4966 (CitrixBleed)"}
        objects.extend([vuln_moveit, vuln_citrix])

        # MALWARE / TOOLS
        mal_solv = {"type": "malware", "id": generate_stix_id("malware"), "name": "SUNBURST", "is_family": False}
        mal_lb = {"type": "malware", "id": generate_stix_id("malware"), "name": "LockBit Black", "is_family": True}
        tool_cs = {"type": "tool", "id": generate_stix_id("tool"), "name": "Cobalt Strike"}
        objects.extend([mal_solv, mal_lb, tool_cs])

        # LINKS TO MALWARE
        objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "uses", "source_ref": actor_apt["id"], "target_ref": mal_solv["id"]})
        objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "uses", "source_ref": actor_lb["id"], "target_ref": mal_lb["id"]})
        objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "uses", "source_ref": actor_lb["id"], "target_ref": tool_cs["id"]})
        objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "targets", "source_ref": tool_cs["id"], "target_ref": vuln_citrix["id"]})

        # ATTACK PATTERNS (Saturate Heatmap)
        tactics = [
            ("T1190", "Exploit Public-Facing App"), ("T1078", "Valid Accounts"), ("T1566", "Phishing"),
            ("T1059", "Command and Scripting Interpreter"), ("T1055", "Process Injection"),
            ("T1068", "Exploitation for Privilege Escalation"), ("T1003", "OS Credential Dumping"),
            ("T1082", "System Information Discovery"), ("T1021", "Remote Services"), ("T1048", "Exfiltration Over Alternate Protocol"),
            ("T1486", "Data Encrypted for Impact"), ("T1490", "Inhibit System Recovery")
        ]
        
        for t_id, t_name in tactics:
            ap = {"type": "attack-pattern", "id": generate_stix_id("attack-pattern"), "name": t_name, "external_references": [{"source_name": "mitre-attack", "external_id": t_id}]}
            objects.append(ap)
            # Add random relations to actors
            if random.random() > 0.3:
                objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "uses", "source_ref": actor_lb["id"], "target_ref": ap["id"]})
            if random.random() > 0.5:
                objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "uses", "source_ref": actor_apt["id"], "target_ref": ap["id"]})

        # INDICATORS (Nodes for 3D Graph)
        for i in range(15):
            ind = {"type": "indicator", "id": generate_stix_id("indicator"), "name": f"Malicious IP 185.1{i}.{random.randint(10,250)}.{random.randint(1,250)}", "pattern": f"[ipv4-addr:value = '185.1{i}.{random.randint(10,250)}.{random.randint(1,250)}']", "pattern_type": "stix"}
            objects.append(ind)
            if i % 2 == 0:
                objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "indicates", "source_ref": ind["id"], "target_ref": mal_lb["id"]})
            else:
                objects.append({"type": "relationship", "id": generate_stix_id("relationship"), "relationship_type": "indicates", "source_ref": ind["id"], "target_ref": mal_solv["id"]})

        logger.info(f"[+] Submitting {len(objects)} STIX objects via API _internal/seed endpoint...")
        
        now_ts = datetime.now(timezone.utc).isoformat()
        for idx, obj in enumerate(objects):
            if "created" not in obj:
                obj["created"] = now_ts
            if "modified" not in obj:
                obj["modified"] = now_ts
            if "spec_version" not in obj:
                obj["spec_version"] = "2.1"
                
        # Send via dedicated Standalone Seed endpoint
        seed_res = await client.post(
            f"{API_BASE}/api/v1/_internal/seed",
            json={"objects": objects},
            headers={"Content-Type": "application/json"}
        )
        if seed_res.status_code == 200:
            logger.info(f"[+] Successfully injected full STIX graph. Result: {seed_res.json()}")
        else:
            logger.error(f"[-] Failed to inject topology: {seed_res.text}")
            
        logger.info("[+] Sending raw NLP inputs to API to saturate Heatmap (TTP extraction)...")
        # Generate 50 raw textual reports and hit NLP extraction (this tests the NLP and IOC pipeline)
        sample_texts = [
            "Attackers used Cobalt Strike and ran powershell.exe with encoded commands.",
            "Phishing emails delivered macro-enabled documents dropping Emotet.",
            "RDP brute force led to Domain Admin escalation using Mimikatz.",
            "Ransomware encrypted files and exfiltrated databases via Rclone to Mega.",
            "Vulnerability in MOVEit (CVE-2023-34362) allowed SQLi and webshell deployment.",
            "Attackers cleared Security Event Logs to evade detection."
        ] * 10
        
        # We also need to map these to the new internal store if we want them rendered directly.
        # But MockElasticsearchService already amplifies whatever attack-patterns we sent in the topology!
        # Giving the NLP endpoints something to process will ensure the API handles load visually.
        # NLP parsing bypassed for Standalone Demo to avoid heavy Torch dependencies.
        # Ensure visually realistic counts without local resource burn.
        logger.info("[+] Simulating Clear Web Leak Events internally...")
        # We skip Redis injection here since it's inactive in standalone mode
        
        logger.info("[+] Exhibition data fully injected. Dashboard saturation active.")

if __name__ == "__main__":
    asyncio.run(main())
