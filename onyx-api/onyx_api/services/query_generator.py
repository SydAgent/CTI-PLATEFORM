"""
GC-01: SIEM Query Generator

Generates KQL / SPL / EQL / Sigma queries from IoC values and ATT&CK techniques.
All templates are deterministic — no LLM call, zero latency.
"""

from __future__ import annotations

import re
import textwrap
from typing import Literal

QueryFormat = Literal["kql", "spl", "eql", "sigma"]

# ─── IoC type → query templates ──────────────────────────────────────────────

_IOC_TEMPLATES: dict[str, dict[QueryFormat, str]] = {
    "ipv4": {
        "kql": (
            "DeviceNetworkEvents\n"
            "| where RemoteIP == \"{value}\"\n"
            "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            'index=* (dest_ip="{value}" OR src_ip="{value}")\n'
            "| table _time, host, src_ip, dest_ip, dest_port, action\n"
            "| sort -_time"
        ),
        "eql": (
            'network where destination.ip == "{value}"\n'
            "| head 100"
        ),
        "sigma": textwrap.dedent("""\
            title: Suspicious connection to {value}
            id: auto-{value_slug}
            status: experimental
            description: Network connection to known threat actor IoC {value}
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    DestinationIp: '{value}'
                condition: selection
            falsepositives:
                - Legitimate business traffic
            level: high
        """),
    },
    "ipv6": {
        "kql": (
            "DeviceNetworkEvents\n"
            "| where RemoteIP == \"{value}\"\n"
            "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            'index=* (dest_ip="{value}" OR src_ip="{value}")\n'
            "| table _time, host, src_ip, dest_ip, dest_port, action"
        ),
        "eql": 'network where destination.ip == "{value}"',
        "sigma": textwrap.dedent("""\
            title: Connection to IPv6 IoC {value}
            id: auto-{value_slug}
            status: experimental
            logsource:
                category: network_connection
            detection:
                selection:
                    DestinationIp: '{value}'
                condition: selection
            level: high
        """),
    },
    "domain": {
        "kql": (
            "DeviceNetworkEvents\n"
            '| where RemoteUrl has "{value}" or RemoteUrl endswith ".{value}"\n'
            "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP\n"
            "| order by Timestamp desc\n"
            "union (\n"
            "    DeviceDnsEvents\n"
            '    | where Name endswith "{value}"\n'
            "    | project Timestamp, DeviceName, Name, IPAddresses\n"
            ")"
        ),
        "spl": (
            'index=* (dest="{value}" OR dns="{value}" OR query="*{value}*")\n'
            "| table _time, host, src_ip, dest, dns, query\n"
            "| sort -_time"
        ),
        "eql": (
            'dns where dns.question.name like~ "*{value}*"\n'
            "| head 100"
        ),
        "sigma": textwrap.dedent("""\
            title: DNS query to C2 domain {value}
            id: auto-{value_slug}
            status: experimental
            description: DNS resolution of known threat actor domain
            logsource:
                category: dns
            detection:
                selection:
                    query|endswith: '{value}'
                condition: selection
            level: high
        """),
    },
    "url": {
        "kql": (
            "DeviceNetworkEvents\n"
            '| where RemoteUrl has "{value}"\n'
            "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            'index=* url="{value}"\n'
            "| table _time, host, src_ip, url, status_code\n"
            "| sort -_time"
        ),
        "eql": 'network where url.full like~ "*{value}*"',
        "sigma": textwrap.dedent("""\
            title: HTTP request to malicious URL {value}
            id: auto-{value_slug}
            status: experimental
            logsource:
                category: webserver
            detection:
                selection:
                    c-uri|contains: '{value}'
                condition: selection
            level: high
        """),
    },
    "sha256": {
        "kql": (
            "DeviceFileEvents\n"
            '| where SHA256 == "{value}"\n'
            "| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName\n"
            "| order by Timestamp desc\n"
            "union (\n"
            "    DeviceProcessEvents\n"
            '    | where SHA256 == "{value}"\n'
            "    | project Timestamp, DeviceName, FileName, ProcessCommandLine\n"
            ")"
        ),
        "spl": (
            'index=* file_hash="{value}"\n'
            "| table _time, host, file_name, file_path, file_hash, action\n"
            "| sort -_time"
        ),
        "eql": 'file where file.hash.sha256 == "{value}"',
        "sigma": textwrap.dedent("""\
            title: Malicious file hash SHA256 {value}
            id: auto-{value_slug}
            status: experimental
            logsource:
                category: file_event
                product: windows
            detection:
                selection:
                    Hashes|contains: 'SHA256={value}'
                condition: selection
            level: critical
        """),
    },
    "sha1": {
        "kql": (
            "DeviceFileEvents\n"
            '| where SHA1 == "{value}"\n'
            "| project Timestamp, DeviceName, FileName, FolderPath\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            'index=* file_hash="{value}"\n'
            "| table _time, host, file_name, file_hash, action"
        ),
        "eql": 'file where file.hash.sha1 == "{value}"',
        "sigma": textwrap.dedent("""\
            title: Malicious file hash SHA1 {value}
            id: auto-{value_slug}
            status: experimental
            logsource:
                category: file_event
            detection:
                selection:
                    Hashes|contains: 'SHA1={value}'
                condition: selection
            level: high
        """),
    },
    "md5": {
        "kql": (
            "DeviceFileEvents\n"
            '| where MD5 == "{value}"\n'
            "| project Timestamp, DeviceName, FileName, FolderPath\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            'index=* file_hash="{value}"\n'
            "| table _time, host, file_name, file_hash, action"
        ),
        "eql": 'file where file.hash.md5 == "{value}"',
        "sigma": textwrap.dedent("""\
            title: Malicious file MD5 {value}
            id: auto-{value_slug}
            status: experimental
            logsource:
                category: file_event
            detection:
                selection:
                    Hashes|contains: 'MD5={value}'
                condition: selection
            level: high
        """),
    },
    "email": {
        "kql": (
            "EmailEvents\n"
            '| where SenderFromAddress == "{value}" or RecipientEmailAddress == "{value}"\n'
            "| project Timestamp, Subject, SenderFromAddress, RecipientEmailAddress, DeliveryAction\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            'index=* (sender="{value}" OR recipient="{value}")\n'
            "| table _time, host, sender, recipient, subject, action"
        ),
        "eql": 'email where email.from.address == "{value}"',
        "sigma": textwrap.dedent("""\
            title: Email from known threat actor address {value}
            id: auto-{value_slug}
            status: experimental
            logsource:
                product: m365
                service: threat_management
            detection:
                selection:
                    SenderAddress: '{value}'
                condition: selection
            level: medium
        """),
    },
    "cve": {
        "kql": (
            "DeviceAlerts\n"
            '| where Title has "{value}"\n'
            "| project Timestamp, DeviceName, Title, Severity, AlertId\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            'index=* cve="{value}"\n'
            "| table _time, host, cve, signature, action"
        ),
        "eql": 'alert where vulnerability.id == "{value}"',
        "sigma": textwrap.dedent("""\
            title: Exploitation attempt for {value}
            id: auto-{value_slug}
            status: experimental
            logsource:
                category: alert
            detection:
                selection:
                    cve: '{value}'
                condition: selection
            level: critical
        """),
    },
}

# Default fallback for unknown IoC types
_DEFAULT_TEMPLATES: dict[QueryFormat, str] = {
    "kql": (
        "// Generic search for {value}\n"
        'search "{value}"\n'
        "| project Timestamp, Computer, EventID, RenderedDescription\n"
        "| order by Timestamp desc"
    ),
    "spl": (
        '"{value}"\n'
        "| table _time, host, source, sourcetype, _raw"
    ),
    "eql": 'any where to_string(*) like~ "*{value}*"',
    "sigma": textwrap.dedent("""\
        title: Generic IoC match for {value}
        id: auto-{value_slug}
        status: experimental
        logsource:
            category: '*'
        detection:
            keywords:
                - '{value}'
            condition: keywords
        level: medium
    """),
}

# ─── ATT&CK technique → query templates ──────────────────────────────────────

_TECHNIQUE_TEMPLATES: dict[str, dict[QueryFormat, str]] = {
    "T1059.001": {
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName =~ 'powershell.exe'\n"
            "| where ProcessCommandLine has_any ('-EncodedCommand', '-enc', 'IEX', 'Invoke-Expression', 'DownloadString')\n"
            "| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            "index=* process_name=powershell.exe\n"
            '    (command_line="*-EncodedCommand*" OR command_line="*-enc*" OR command_line="*IEX*")\n'
            "| table _time, host, user, command_line"
        ),
        "eql": (
            "process where process.name == \"powershell.exe\"\n"
            "  and process.command_line like~ \"*-EncodedCommand*\""
        ),
        "sigma": textwrap.dedent("""\
            title: Suspicious PowerShell Execution (T1059.001)
            id: auto-T1059-001
            status: stable
            description: Detects suspicious encoded or download cradle PowerShell usage
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\\powershell.exe'
                    CommandLine|contains:
                        - '-EncodedCommand'
                        - '-enc '
                        - 'IEX('
                        - 'Invoke-Expression'
                        - 'DownloadString'
                condition: selection
            level: high
        """),
    },
    "T1071.001": {
        "kql": (
            "DeviceNetworkEvents\n"
            "| where RemotePort in (80, 443, 8080, 8443)\n"
            "| where InitiatingProcessFileName in~ ('cmd.exe','powershell.exe','wscript.exe','cscript.exe','mshta.exe')\n"
            "| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            "index=* dest_port IN (80, 443) process IN (cmd.exe, powershell.exe, wscript.exe)\n"
            "| table _time, host, process, dest_ip, dest_port, bytes_out"
        ),
        "eql": (
            "network where destination.port in (80, 443)\n"
            "  and process.name in (\"cmd.exe\", \"powershell.exe\", \"wscript.exe\")"
        ),
        "sigma": textwrap.dedent("""\
            title: C2 via HTTP/S from scripting engine (T1071.001)
            id: auto-T1071-001
            status: experimental
            logsource:
                category: network_connection
                product: windows
            detection:
                selection:
                    Image|endswith:
                        - '\\cmd.exe'
                        - '\\powershell.exe'
                        - '\\wscript.exe'
                    DestinationPort:
                        - 80
                        - 443
                condition: selection
            level: medium
        """),
    },
    "T1566": {
        "kql": (
            "EmailEvents\n"
            "| where DeliveryAction != 'Delivered'\n"
            "| where ThreatTypes has_any ('Phish', 'Malware')\n"
            "| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            "index=email sourcetype=exchange\n"
            "| where threat_type IN (\"Phish\", \"Malware\")\n"
            "| table _time, sender, recipient, subject, threat_type"
        ),
        "eql": 'email where email.threat_type == "phish"',
        "sigma": textwrap.dedent("""\
            title: Phishing email detected (T1566)
            id: auto-T1566
            status: stable
            logsource:
                product: m365
                service: threat_management
            detection:
                selection:
                    ThreatTypes|contains: 'Phish'
                condition: selection
            level: high
        """),
    },
    "T1486": {
        "kql": (
            "DeviceFileEvents\n"
            "| where ActionType == 'FileModified'\n"
            "| where FileName endswith_cs '.encrypted' or FileName endswith_cs '.locked' or FileName endswith_cs '.cry'\n"
            "| summarize count() by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1m)\n"
            "| where count_ > 50\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            "index=* action=modified (file_name=\"*.encrypted\" OR file_name=\"*.locked\")\n"
            "| stats count by host, process | where count > 50"
        ),
        "eql": (
            "file where file.name like~ \"*.encrypted\"\n"
            "| head 100"
        ),
        "sigma": textwrap.dedent("""\
            title: Mass file encryption — ransomware indicator (T1486)
            id: auto-T1486
            status: experimental
            logsource:
                category: file_event
                product: windows
            detection:
                selection:
                    TargetFilename|endswith:
                        - '.encrypted'
                        - '.locked'
                        - '.cry'
                        - '.enc'
                condition: selection
            level: critical
        """),
    },
    "T1055": {
        "kql": (
            "DeviceEvents\n"
            "| where ActionType == 'CreateRemoteThread'\n"
            "| project Timestamp, DeviceName, InitiatingProcessFileName, TargetProcessId, TargetProcessFileName\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            "index=* action=CreateRemoteThread\n"
            "| table _time, host, source_process, target_process, target_pid"
        ),
        "eql": 'process where process.parent.name != process.name and event.action == "inject"',
        "sigma": textwrap.dedent("""\
            title: Remote thread creation (process injection T1055)
            id: auto-T1055
            status: stable
            logsource:
                category: create_remote_thread
                product: windows
            detection:
                selection:
                    TargetImage|endswith:
                        - '\\svchost.exe'
                        - '\\explorer.exe'
                        - '\\lsass.exe'
                condition: selection
            level: high
        """),
    },
    "T1003": {
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName =~ 'mimikatz.exe'\n"
            "    or ProcessCommandLine has_any ('sekurlsa', 'lsadump', 'kerberos::list', 'token::elevate')\n"
            "| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine\n"
            "| order by Timestamp desc"
        ),
        "spl": (
            "index=* (process=mimikatz.exe OR command_line=\"*sekurlsa*\" OR command_line=\"*lsadump*\")\n"
            "| table _time, host, user, process, command_line"
        ),
        "eql": (
            "process where process.name == \"mimikatz.exe\"\n"
            "  or process.command_line like~ \"*sekurlsa*\""
        ),
        "sigma": textwrap.dedent("""\
            title: Credential dumping via Mimikatz (T1003)
            id: auto-T1003
            status: stable
            logsource:
                category: process_creation
                product: windows
            detection:
                selection:
                    Image|endswith: '\\mimikatz.exe'
                selection_cmdline:
                    CommandLine|contains:
                        - 'sekurlsa'
                        - 'lsadump'
                        - 'kerberos::list'
                condition: selection or selection_cmdline
            level: critical
        """),
    },
}


def _slug(value: str) -> str:
    """Make a safe slug from an IoC value for use in Sigma rule IDs."""
    return re.sub(r"[^a-zA-Z0-9]", "-", value)[:40].strip("-")


class QueryGenerator:
    """
    Generate SIEM detection queries for IoC values and ATT&CK techniques.

    All methods are synchronous and free of I/O — safe to call in any context.
    """

    def generate_ioc_queries(
        self,
        ioc_type: str,
        ioc_value: str,
        formats: list[QueryFormat] | None = None,
    ) -> dict[str, str]:
        """Return {format: query} for the given IoC value."""
        requested = formats or ["kql", "spl", "eql", "sigma"]
        templates = _IOC_TEMPLATES.get(ioc_type, _DEFAULT_TEMPLATES)
        slug = _slug(ioc_value)
        return {
            fmt: templates.get(fmt, _DEFAULT_TEMPLATES.get(fmt, "// unsupported format")).format(
                value=ioc_value,
                value_slug=slug,
            )
            for fmt in requested
        }

    def generate_technique_queries(
        self,
        technique_id: str,
        formats: list[QueryFormat] | None = None,
    ) -> dict[str, str] | None:
        """Return {format: query} for the given ATT&CK technique ID, or None if unknown."""
        templates = _TECHNIQUE_TEMPLATES.get(technique_id)
        if templates is None:
            return None
        requested = formats or ["kql", "spl", "eql", "sigma"]
        return {fmt: templates[fmt] for fmt in requested if fmt in templates}

    def supported_techniques(self) -> list[str]:
        return list(_TECHNIQUE_TEMPLATES.keys())

    def supported_ioc_types(self) -> list[str]:
        return list(_IOC_TEMPLATES.keys())


# Module-level singleton
query_generator = QueryGenerator()
