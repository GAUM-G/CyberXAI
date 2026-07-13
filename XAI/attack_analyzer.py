"""
Attack Analyzer Module
Extracts detailed information about attacks for XAI reporting
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class AttackSignature:
    """Signature of an attack pattern"""
    pattern_type: str
    severity_level: str
    indicators: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    risk_score: float = 0.0


@dataclass
class AttackerProfile:
    """Profile of an attacker"""
    source_ip: str
    first_seen: str
    last_seen: str
    total_events: int
    attack_types: list[str] = field(default_factory=list)
    services_targeted: list[str] = field(default_factory=list)
    credentials_attempted: list[str] = field(default_factory=list)
    files_accessed: list[str] = field(default_factory=list)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    attack_signatures: list[AttackSignature] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    extracted_payloads: list[str] = field(default_factory=list)
    commands_executed: list[str] = field(default_factory=list)
    geographic_info: dict[str, Any] = field(default_factory=dict)
    behavioral_patterns: dict[str, Any] = field(default_factory=dict)


class AttackAnalyzer:
    """Analyzes raw honeypot events and extracts attack information"""

    CRITICAL_EVENTS = {
        "ftp_login_success",
        "ftp_file_download",
        "http_malicious_payload",
        "website_login_attempt",
        "sql_injection",
        "ssh_login_success",
    }

    ATTACK_TECHNIQUE_MAPPING = {
        "sql_injection": ["SQL Injection", "T1190"],
        "credential_access": ["Credential Access", "T1110"],
        "command_activity": ["Command Execution", "T1059"],
        "connection_probe": ["Reconnaissance", "T1046"],
        "web_activity": ["Web Application Attack", "T1190"],
        "authentication_probe": ["Credential Guessing", "T1110"],
    }

    def __init__(self):
        """Initialize the attack analyzer"""
        self.attacker_profiles: dict[str, AttackerProfile] = {}

    def analyze_event(self, event: dict[str, Any]) -> None:
        """Analyze a single honeypot event"""
        source_ip = event.get("source_ip", "unknown")

        if source_ip not in self.attacker_profiles:
            self.attacker_profiles[source_ip] = AttackerProfile(
                source_ip=source_ip,
                first_seen=event.get("timestamp", ""),
                last_seen=event.get("timestamp", ""),
                total_events=0,
            )

        profile = self.attacker_profiles[source_ip]
        profile.total_events += 1
        profile.last_seen = event.get("timestamp", profile.last_seen)

        # Extract attack type
        attack_type = event.get("attack_type", "unknown")
        if attack_type not in profile.attack_types:
            profile.attack_types.append(attack_type)

        # Extract service
        service = event.get("service", "unknown")
        if service not in profile.services_targeted:
            profile.services_targeted.append(service)

        # Extract severity distribution
        severity = event.get("severity", "info")
        profile.severity_distribution[severity] = (
            profile.severity_distribution.get(severity, 0) + 1
        )

        # Extract credentials
        metadata = event.get("metadata", {})
        if isinstance(metadata, dict):
            username = metadata.get("username")
            if username and username not in profile.credentials_attempted:
                profile.credentials_attempted.append(username)

        # Extract files accessed
        payload = event.get("payload", "")
        event_type = event.get("event", "")
        if "RETR" in str(payload) or "file" in event_type.lower():
            if isinstance(payload, str) and payload not in profile.files_accessed:
                profile.files_accessed.append(payload)

        # Extract commands (FTP, SSH, HTTP)
        if "command" in metadata and isinstance(metadata.get("command"), str):
            command = metadata.get("command")
            if command not in profile.commands_executed:
                profile.commands_executed.append(command)

        # Add to timeline
        timeline_entry = {
            "timestamp": event.get("timestamp"),
            "event": event.get("event"),
            "attack_type": attack_type,
            "payload": self._sanitize_payload(payload),
            "severity": severity,
        }
        profile.timeline.append(timeline_entry)

        # Extract payloads for analysis
        if isinstance(payload, str) and len(payload) > 0:
            payload_hash = hash(payload) % 100000
            payload_entry = f"{payload[:100]}... [hash:{payload_hash}]"
            if payload_entry not in profile.extracted_payloads:
                profile.extracted_payloads.append(payload_entry)

        # Generate attack signatures
        self._update_attack_signatures(profile, event)

        # Update behavioral patterns
        self._update_behavioral_patterns(profile, event)

    def _sanitize_payload(self, payload: Any) -> str:
        """Sanitize payload for reporting"""
        if isinstance(payload, dict):
            return json.dumps(payload)
        payload_str = str(payload)
        if len(payload_str) > 200:
            return payload_str[:200] + "..."
        return payload_str

    def _update_attack_signatures(
        self, profile: AttackerProfile, event: dict[str, Any]
    ) -> None:
        """Update attack signatures based on event"""
        attack_type = event.get("attack_type", "")
        severity = event.get("severity", "info")

        techniques = self.ATTACK_TECHNIQUE_MAPPING.get(attack_type, [attack_type])

        signature = AttackSignature(
            pattern_type=event.get("event", "unknown"),
            severity_level=severity,
            techniques=techniques,
            risk_score=self._calculate_risk_score(event),
        )

        # Check if similar signature exists
        similar = any(
            s.pattern_type == signature.pattern_type for s in profile.attack_signatures
        )
        if not similar:
            profile.attack_signatures.append(signature)

    def _update_behavioral_patterns(
        self, profile: AttackerProfile, event: dict[str, Any]
    ) -> None:
        """Update behavioral patterns"""
        if "behavioral_patterns" not in profile.behavioral_patterns:
            profile.behavioral_patterns = {
                "persistence_attempts": 0,
                "credential_guesses": 0,
                "reconnaissance_scans": 0,
                "data_exfiltration": 0,
            }

        attack_type = event.get("attack_type", "")

        if attack_type == "credential_access":
            profile.behavioral_patterns["credential_guesses"] += 1
        elif attack_type == "connection_probe":
            profile.behavioral_patterns["reconnaissance_scans"] += 1
        elif "file" in event.get("event", "").lower():
            profile.behavioral_patterns["data_exfiltration"] += 1

    def _calculate_risk_score(self, event: dict[str, Any]) -> float:
        """Calculate risk score for an event"""
        score = 0.0

        severity = event.get("severity", "info")
        severity_weights = {"critical": 1.0, "warning": 0.6, "info": 0.2}
        score += severity_weights.get(severity, 0.2)

        attack_type = event.get("attack_type", "")
        high_risk_types = {"credential_access", "sql_injection", "command_activity"}
        if attack_type in high_risk_types:
            score += 0.5

        return min(score, 1.0)

    def get_attacker_profile(self, source_ip: str) -> Optional[AttackerProfile]:
        """Get profile for a specific attacker"""
        return self.attacker_profiles.get(source_ip)

    def get_all_profiles(self) -> dict[str, AttackerProfile]:
        """Get all attacker profiles"""
        return self.attacker_profiles

    def get_high_risk_attackers(self, threshold: float = 0.7) -> list[AttackerProfile]:
        """Get attackers with high risk profiles"""
        high_risk = []
        for profile in self.attacker_profiles.values():
            avg_risk = sum(
                s.risk_score for s in profile.attack_signatures
            ) / max(len(profile.attack_signatures), 1)
            if avg_risk >= threshold or "critical" in profile.severity_distribution:
                high_risk.append(profile)
        return high_risk

    def export_profile_to_dict(self, profile: AttackerProfile) -> dict[str, Any]:
        """Export attacker profile as dictionary"""
        return asdict(profile)

    def export_all_profiles_to_dict(self) -> dict[str, dict[str, Any]]:
        """Export all profiles as dictionaries"""
        return {ip: asdict(profile) for ip, profile in self.attacker_profiles.items()}
