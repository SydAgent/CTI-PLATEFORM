import re
from typing import Tuple

class CTSecurityFilter:
    """
    Validates that incoming prompts are strictly within the scope of
    Cyber Threat Intelligence (CTI), OSINT, and Dark Web analysis.
    """
    
    # Allowed CTI concepts
    CTI_KEYWORDS = [
        r'ransomware', r'lockbit', r'blackcat', r'clop', r'phishing',
        r'ioc', r'ip', r'hash', r'domain', r'url', r'cve', r'vulnerability',
        r'exploit', r'dark web', r'deep web', r'tor', r'onion', r'leak',
        r'breach', r'pastebin', r'credentials', r'malware', r'botnet',
        r'ddos', r'apt', r'threat', r'actor', r'attack', r'campaign',
        r'remediation', r'mitigation', r'soc', r'siem'
    ]
    
    # Blocked concepts (offensive / unauthorized)
    OFFENSIVE_KEYWORDS = [
        r'write an exploit', r'how to hack', r'generate payload',
        r'reverse shell', r'bypass antivirus', r'create malware'
    ]
    
    @classmethod
    def validate_prompt(cls, prompt: str) -> Tuple[bool, str]:
        """
        Returns (is_valid, reason)
        """
        prompt_lower = prompt.lower()
        
        # 1. Check for offensive instructions first
        for block_pattern in cls.OFFENSIVE_KEYWORDS:
            if re.search(block_pattern, prompt_lower):
                return False, "BLOCKED: Offensive intent or exploit generation detected."
                
        # 2. Heuristic check: Ensure topic is roughly CTI
        # For a production system this could be an ML classifier.
        # Here we use keyword prevalence.
        match_count = sum(1 for kw in cls.CTI_KEYWORDS if re.search(kw, prompt_lower))
        
        if match_count == 0:
            # If the query is just an IP or standard hello, we might want to allow it, 
            # but in strict mode we demand context.
            # We will allow very short queries (like just an IP) via regex
            ip_pattern = r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'
            hash_pattern = r'^[a-fA-F0-9]{32,64}$'
            if re.match(ip_pattern, prompt) or re.match(hash_pattern, prompt):
                return True, "Valid IOC format detected."
            
            # Simple permissive fallback for general tech/cyber questions
            # For strict mode, if it's longer than 10 words and has 0 CTI keywords, block it.
            if len(prompt.split()) > 10:
                return False, "OUT OF SCOPE: Query does not contain relevant CTI/OSINT context."
        
        return True, "Valid CTI Context"
