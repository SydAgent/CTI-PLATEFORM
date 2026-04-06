"""
ONYX CTI — ATT&CK TTP Mapper (SciBERT)
Maps raw threat intelligence text to MITRE ATT&CK techniques using a
fine-tuned SciBERT model and a fallback keyword-based classifier.

Pattern source: TRAM's BERTClassifierModel — predict_samples(),
_sentence_tokenize() with sliding window, and confidence thresholding.
We adapt the TRAM pipeline to work standalone without Django ORM,
using HuggingFace Transformers directly with GPU/CPU auto-detection.

Dual-mode operation:
1. ML Mode: SciBERT model for high-accuracy technique classification
2. Keyword Mode: Deterministic keyword matching as fallback/supplement
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("onyx.nlp.ttp_mapper")


@dataclass
class TTPMapping:
    """A single ATT&CK technique mapping with confidence."""
    technique_id: str       # e.g., T1566.001
    technique_name: str     # e.g., "Phishing: Spearphishing Attachment"
    tactic: str             # e.g., "initial-access"
    confidence: float       # 0.0-1.0
    source_text: str = ""   # The text segment that triggered this mapping
    method: str = "keyword" # "scibert" or "keyword"


@dataclass
class TTPResult:
    """Complete TTP mapping result for a document."""
    techniques: list[TTPMapping] = field(default_factory=list)
    top_tactics: list[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    model_used: str = "keyword"


# ============================================================================
# MITRE ATT&CK Technique Keyword Map
# Comprehensive keyword → technique mapping for deterministic classification.
# This serves as Day-1 fallback when SciBERT model is loading.
# ============================================================================
ATTACK_KEYWORD_MAP: dict[str, dict[str, Any]] = {
    "T1566": {
        "name": "Phishing",
        "tactic": "initial-access",
        "keywords": [
            "phishing", "spearphishing", "spear-phishing", "email lure",
            "malicious attachment", "macro-enabled", "social engineering email",
            "business email compromise", "bec", "credential harvesting email",
        ],
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "initial-access",
        "keywords": [
            "spearphishing attachment", "malicious document", "weaponized document",
            "macro payload", "doc dropper", "excel macro", "maldoc",
        ],
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "initial-access",
        "keywords": [
            "spearphishing link", "malicious url", "credential phishing",
            "phishing url", "fake login",
        ],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "keywords": [
            "exploit", "rce", "remote code execution", "vulnerability exploitation",
            "web shell", "sql injection", "sqli", "command injection",
            "zero-day", "0-day", "cve-202", "exploit public",
        ],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial-access",
        "keywords": [
            "valid accounts", "stolen credentials", "compromised credentials",
            "credential stuffing", "default credentials", "leaked credentials",
            "credential dump", "brute force login",
        ],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "keywords": [
            "powershell", "cmd.exe", "bash", "python script", "vbscript",
            "wscript", "cscript", "javascript execution", "mshta",
        ],
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "execution",
        "keywords": [
            "powershell", "invoke-expression", "iex", "downloadstring",
            "encoded command", "bypass execution policy", "powershell empire",
        ],
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "execution",
        "keywords": [
            "user execution", "clicked link", "opened attachment",
            "ran macro", "enabled content", "social engineering",
        ],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "persistence",
        "keywords": [
            "scheduled task", "cron job", "task scheduler", "at command",
            "persistence mechanism", "schtasks",
        ],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "persistence",
        "keywords": [
            "registry run key", "startup folder", "autostart", "boot persistence",
            "login script", "winlogon", "autorun",
        ],
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "defense-evasion",
        "keywords": [
            "process injection", "dll injection", "process hollowing",
            "reflective injection", "thread injection", "apc injection",
            "createremotethread",
        ],
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "defense-evasion",
        "keywords": [
            "obfuscation", "packed", "encrypted payload", "base64 encoded",
            "string obfuscation", "code obfuscation", "packing",
            "custom encryption", "xor encoded",
        ],
    },
    "T1036": {
        "name": "Masquerading",
        "tactic": "defense-evasion",
        "keywords": [
            "masquerading", "renamed binary", "fake process", "mimicking",
            "legitimate process name", "disguised as",
        ],
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "credential-access",
        "keywords": [
            "credential dumping", "mimikatz", "lsass", "sam database",
            "ntds.dit", "hashdump", "secretsdump", "credential extraction",
            "pass-the-hash", "kerberoasting",
        ],
    },
    "T1110": {
        "name": "Brute Force",
        "tactic": "credential-access",
        "keywords": [
            "brute force", "password spraying", "credential stuffing",
            "dictionary attack", "hydra", "medusa brute", "password guessing",
        ],
    },
    "T1087": {
        "name": "Account Discovery",
        "tactic": "discovery",
        "keywords": [
            "account discovery", "user enumeration", "net user",
            "domain users", "whoami", "account enumeration",
        ],
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "discovery",
        "keywords": [
            "system information", "systeminfo", "uname", "host reconnaissance",
            "os fingerprinting", "system discovery", "enumeration",
        ],
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "lateral-movement",
        "keywords": [
            "lateral movement", "rdp", "remote desktop", "ssh", "smb",
            "psexec", "wmi", "winrm", "remote services",
        ],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "keywords": [
            "command and control", "c2", "c&c", "beacon", "callback",
            "http c2", "https c2", "dns tunneling", "c2 channel",
            "cobalt strike", "cobaltstrike",
        ],
    },
    "T1105": {
        "name": "Ingress Tool Transfer",
        "tactic": "command-and-control",
        "keywords": [
            "tool transfer", "download payload", "stage 2", "second stage",
            "dropper", "downloader", "payload delivery", "wget", "curl",
            "certutil download",
        ],
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "exfiltration",
        "keywords": [
            "exfiltration", "data exfiltration", "data theft", "data staging",
            "exfil over c2", "data collection", "archive collected",
        ],
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "exfiltration",
        "keywords": [
            "exfiltration web", "cloud storage exfil", "mega.nz",
            "dropbox exfil", "google drive exfil", "pastebin upload",
            "data upload", "rclone",
        ],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "tactic": "impact",
        "keywords": [
            "ransomware", "ransom", "encryption", "encrypted files",
            "decrypt key", "ransom note", "bitcoin ransom",
            "file encryption", "data encrypted", "lockbit", "blackcat",
        ],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "tactic": "impact",
        "keywords": [
            "shadow copy", "vssadmin delete", "bcdedit", "disable recovery",
            "wbadmin delete", "shadow copies deleted", "backup deletion",
        ],
    },
    "T1489": {
        "name": "Service Stop",
        "tactic": "impact",
        "keywords": [
            "service stop", "kill process", "taskkill", "stop service",
            "disable antivirus", "kill av", "terminate process",
        ],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "exfiltration",
        "keywords": [
            "dns exfiltration", "icmp tunnel", "ftp exfil",
            "alternative protocol", "covert channel",
        ],
    },
}


class TTPMapper:
    """
    Maps text to MITRE ATT&CK techniques using keyword matching
    and optionally SciBERT ML classification.
    
    Adapted from TRAM's ModelManager + BERTClassifierModel:
    - Sentence tokenization with sliding window (stride=5, n=13)
    - SciBERT prediction with softmax probabilities
    - Confidence thresholding (configurable, default 25%)
    - Fallback to keyword matching when model is unavailable
    """

    def __init__(
        self,
        confidence_threshold: float = 0.25,
        use_ml: bool = False,
        model_path: str | None = None,
    ) -> None:
        self.confidence_threshold = confidence_threshold
        self.use_ml = use_ml
        self._model = None
        self._tokenizer = None
        self._classes: tuple[str, ...] = ()

        if use_ml and model_path:
            self._load_model(model_path)

    def _load_model(self, model_path: str) -> None:
        """
        Load fine-tuned SciBERT model and tokenizer.
        Adapted from TRAM's BERTClassifierModel.__init__().
        """
        try:
            import torch
            from transformers import AutoTokenizer, BertForSequenceClassification

            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            logger.info("Loading SciBERT model from %s (device: %s)", model_path, device)

            self._tokenizer = AutoTokenizer.from_pretrained(
                f"{model_path}/scibert-tokenizer"
            )
            self._model = (
                BertForSequenceClassification.from_pretrained(f"{model_path}/bert_model")
                .eval()
                .to(device)
            )

            # Load class labels
            classes_file = f"{model_path}/bert_model/classes.txt"
            with open(classes_file) as f:
                self._classes = tuple(f.read().split())

            self._device = device
            self.use_ml = True
            logger.info(
                "SciBERT loaded — %d technique classes, device: %s",
                len(self._classes),
                device,
            )
        except Exception as e:
            logger.warning("Failed to load SciBERT model: %s — falling back to keywords", str(e))
            self.use_ml = False

    def map_text(self, text: str) -> TTPResult:
        """
        Map a text document to ATT&CK techniques.
        
        Uses keyword matching as the primary method, with SciBERT
        as an enhancement layer when available.
        """
        import time
        start = time.monotonic()
        result = TTPResult()

        # Layer 1: Keyword-based mapping (always runs — high precision)
        keyword_mappings = self._keyword_mapping(text)
        result.techniques.extend(keyword_mappings)

        # Layer 2: SciBERT ML mapping (if available — higher recall)
        if self.use_ml and self._model is not None:
            ml_mappings = self._ml_mapping(text)
            # Merge: boost confidence if both methods agree
            result.techniques = self._merge_mappings(keyword_mappings, ml_mappings)
            result.model_used = "scibert+keyword"
        else:
            result.model_used = "keyword"

        # Deduplicate by technique_id (keep highest confidence)
        seen: dict[str, TTPMapping] = {}
        for mapping in result.techniques:
            if mapping.technique_id not in seen or mapping.confidence > seen[mapping.technique_id].confidence:
                seen[mapping.technique_id] = mapping
        result.techniques = sorted(seen.values(), key=lambda m: m.confidence, reverse=True)

        # Compute top tactics
        tactic_scores: dict[str, float] = {}
        for m in result.techniques:
            tactic_scores[m.tactic] = tactic_scores.get(m.tactic, 0) + m.confidence
        result.top_tactics = sorted(tactic_scores, key=tactic_scores.get, reverse=True)  # type: ignore

        elapsed = (time.monotonic() - start) * 1000
        result.processing_time_ms = round(elapsed, 2)

        logger.info(
            "TTP mapping: %d techniques across %d tactics (%.1fms, model: %s)",
            len(result.techniques),
            len(result.top_tactics),
            result.processing_time_ms,
            result.model_used,
        )

        return result

    def _keyword_mapping(self, text: str) -> list[TTPMapping]:
        """
        Deterministic keyword-based ATT&CK mapping.
        Scans text for technique-specific keywords with context extraction.
        """
        mappings: list[TTPMapping] = []
        text_lower = text.lower()

        for tech_id, tech_info in ATTACK_KEYWORD_MAP.items():
            for keyword in tech_info["keywords"]:
                if keyword in text_lower:
                    # Find the keyword in text for context extraction
                    idx = text_lower.index(keyword)
                    context_start = max(0, idx - 100)
                    context_end = min(len(text), idx + len(keyword) + 100)

                    mappings.append(TTPMapping(
                        technique_id=tech_id,
                        technique_name=tech_info["name"],
                        tactic=tech_info["tactic"],
                        confidence=0.7,  # Keyword match = 70% confidence
                        source_text=text[context_start:context_end],
                        method="keyword",
                    ))
                    break  # One match per technique is sufficient

        return mappings

    def _ml_mapping(self, text: str) -> list[TTPMapping]:
        """
        SciBERT-based ATT&CK mapping.
        Adapted from TRAM's BERTClassifierModel.predict_samples() and
        _sentence_tokenize() with sliding window approach.
        """
        if not self._model or not self._tokenizer:
            return []

        import torch

        mappings: list[TTPMapping] = []

        # TRAM's sentence tokenization: sliding window (stride=5, n=13 words)
        words = text.split()
        stride = 5
        window_size = 13
        segments = [
            " ".join(words[i:i + window_size])
            for i in range(0, max(1, len(words) - window_size + 1), stride)
        ]

        if not segments:
            return mappings

        # Batch prediction (TRAM's batch_size=20 pattern)
        batch_size = 20
        all_probs = []

        with torch.no_grad():
            for i in range(0, len(segments), batch_size):
                batch = segments[i:i + batch_size]
                tokens = self._tokenizer(
                    batch,
                    return_tensors="pt",
                    padding="max_length",
                    truncation=True,
                    max_length=512,
                ).input_ids.to(self._device)

                logits = self._model(
                    tokens,
                    attention_mask=tokens.ne(self._tokenizer.pad_token_id).to(int),
                ).logits
                probs = logits.softmax(-1).cpu()
                all_probs.append(probs)

        # Aggregate predictions across segments
        combined_probs = torch.vstack(all_probs)
        # Take max probability per technique across all segments
        max_probs, _ = combined_probs.max(dim=0)

        for idx, tech_id in enumerate(self._classes):
            prob = float(max_probs[idx])
            if prob >= self.confidence_threshold:
                tech_info = ATTACK_KEYWORD_MAP.get(tech_id, {})
                mappings.append(TTPMapping(
                    technique_id=tech_id,
                    technique_name=tech_info.get("name", tech_id),
                    tactic=tech_info.get("tactic", "unknown"),
                    confidence=round(prob, 4),
                    method="scibert",
                ))

        return mappings

    def _merge_mappings(
        self,
        keyword_mappings: list[TTPMapping],
        ml_mappings: list[TTPMapping],
    ) -> list[TTPMapping]:
        """
        Merge keyword and ML mappings. When both agree on a technique,
        boost confidence. This cross-validation reduces false positives.
        """
        merged: list[TTPMapping] = []
        kw_ids = {m.technique_id for m in keyword_mappings}
        ml_ids = {m.technique_id for m in ml_mappings}

        # Techniques found by both methods get boosted confidence
        agreed = kw_ids & ml_ids
        for tech_id in agreed:
            kw_m = next(m for m in keyword_mappings if m.technique_id == tech_id)
            ml_m = next(m for m in ml_mappings if m.technique_id == tech_id)
            merged.append(TTPMapping(
                technique_id=tech_id,
                technique_name=kw_m.technique_name,
                tactic=kw_m.tactic,
                confidence=min(0.99, max(kw_m.confidence, ml_m.confidence) * 1.2),
                source_text=kw_m.source_text,
                method="scibert+keyword",
            ))

        # Techniques found by only one method
        for m in keyword_mappings:
            if m.technique_id not in agreed:
                merged.append(m)
        for m in ml_mappings:
            if m.technique_id not in agreed:
                merged.append(m)

        return merged
