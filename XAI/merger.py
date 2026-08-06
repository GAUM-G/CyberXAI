"""
XAI Merger Module
Merges attack data and sends to n8n webhook for backend processing
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if __package__:
    from .attack_analyzer import AttackAnalyzer, AttackerProfile
else:
    from attack_analyzer import AttackAnalyzer, AttackerProfile
from core.time_utils import now_ist_iso


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class XAIMerger:
    """Merges attack data and sends to n8n webhook"""

    def __init__(
        self,
        webhook_url: str,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
    ):
        """
        Initialize XAI Merger

        Args:
            webhook_url: N8n webhook URL
            timeout_seconds: Request timeout in seconds
            max_retries: Maximum number of retry attempts
        """
        self.webhook_url = webhook_url
        self.timeout_seconds = timeout_seconds
        self.session = self._create_session(max_retries)
        self.analyzer = AttackAnalyzer()

    def _create_session(self, max_retries: int) -> requests.Session:
        """Create requests session with retry strategy"""
        session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def load_events_from_jsonl(self, file_path: Path) -> list[dict[str, Any]]:
        """
        Load events from JSONL file

        Args:
            file_path: Path to JSONL file

        Returns:
            List of event dictionaries
        """
        events = []
        try:
            with open(file_path, "r") as f:
                for line in f:
                    if line.strip():
                        try:
                            event = json.loads(line)
                            events.append(event)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse line: {e}")
                            continue
            logger.info(f"Loaded {len(events)} events from {file_path}")
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            raise

        return events

    def process_events(self, events: list[dict[str, Any]]) -> None:
        """
        Process events through analyzer

        Args:
            events: List of event dictionaries
        """
        for event in events:
            self.analyzer.analyze_event(event)
        logger.info(
            f"Processed {len(events)} events. "
            f"Found {len(self.analyzer.get_all_profiles())} unique attackers"
        )

    def build_xai_report(self) -> dict[str, Any]:
        """
        Build comprehensive XAI report from analyzed data

        Returns:
            Dictionary containing XAI report
        """
        profiles = self.analyzer.get_all_profiles()
        high_risk_attackers = self.analyzer.get_high_risk_attackers()

        report = {
            "report_metadata": {
                "generated_at": now_ist_iso(),
                "total_attackers": len(profiles),
                "high_risk_attackers": len(high_risk_attackers),
                "analyzer_version": "1.0",
            },
            "summary": self._generate_summary(profiles),
            "attackers": self._build_attacker_data(profiles),
            "high_risk_threats": self._build_threat_data(high_risk_attackers),
            "attack_statistics": self._generate_statistics(profiles),
            "recommendations": self._generate_recommendations(profiles),
        }

        return report

    def _generate_summary(self, profiles: dict[str, AttackerProfile]) -> dict[str, Any]:
        """Generate summary statistics"""
        total_events = sum(p.total_events for p in profiles.values())
        all_attack_types = set()
        all_services = set()
        severity_count = {}

        for profile in profiles.values():
            all_attack_types.update(profile.attack_types)
            all_services.update(profile.services_targeted)
            for severity, count in profile.severity_distribution.items():
                severity_count[severity] = severity_count.get(severity, 0) + count

        return {
            "total_events": total_events,
            "total_attackers": len(profiles),
            "unique_attack_types": len(all_attack_types),
            "services_targeted": list(all_services),
            "severity_distribution": severity_count,
        }

    def _build_attacker_data(
        self, profiles: dict[str, AttackerProfile]
    ) -> list[dict[str, Any]]:
        """Build detailed attacker data"""
        attackers_data = []

        for profile in profiles.values():
            attacker = {
                "source_ip": profile.source_ip,
                "first_seen": profile.first_seen,
                "last_seen": profile.last_seen,
                "total_events": profile.total_events,
                "attack_profile": {
                    "attack_types": profile.attack_types,
                    "services_targeted": profile.services_targeted,
                    "credentials_attempted": profile.credentials_attempted,
                    "files_accessed": profile.files_accessed,
                    "commands_executed": profile.commands_executed,
                    "severity_distribution": profile.severity_distribution,
                },
                "attack_signatures": [
                    {
                        "pattern_type": sig.pattern_type,
                        "severity_level": sig.severity_level,
                        "techniques": sig.techniques,
                        "risk_score": sig.risk_score,
                    }
                    for sig in profile.attack_signatures
                ],
                "behavioral_patterns": profile.behavioral_patterns,
                "timeline_events": profile.timeline[:50],  # Limit timeline to last 50 events
                "extracted_payloads": profile.extracted_payloads[:20],  # Limit payloads
            }

            attackers_data.append(attacker)

        return attackers_data

    def _build_threat_data(
        self, high_risk_attackers: list[AttackerProfile]
    ) -> list[dict[str, Any]]:
        """Build threat data for high-risk attackers"""
        threats = []

        for profile in high_risk_attackers:
            threat_level = "critical" if "critical" in profile.severity_distribution else "high"

            threat = {
                "source_ip": profile.source_ip,
                "threat_level": threat_level,
                "critical_events": profile.severity_distribution.get("critical", 0),
                "warning_events": profile.severity_distribution.get("warning", 0),
                "primary_attack_types": profile.attack_types[:3],
                "compromised_services": profile.services_targeted,
                "extracted_credentials": profile.credentials_attempted,
                "accessed_resources": profile.files_accessed,
                "risk_indicators": self._generate_risk_indicators(profile),
            }

            threats.append(threat)

        return threats

    def _generate_statistics(
        self, profiles: dict[str, AttackerProfile]
    ) -> dict[str, Any]:
        """Generate attack statistics"""
        attack_type_counts = {}
        service_counts = {}
        event_counts_per_ip = {}

        for profile in profiles.values():
            for attack_type in profile.attack_types:
                attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

            for service in profile.services_targeted:
                service_counts[service] = service_counts.get(service, 0) + 1

            event_counts_per_ip[profile.source_ip] = profile.total_events

        return {
            "attack_type_distribution": attack_type_counts,
            "service_targeting_distribution": service_counts,
            "events_per_attacker": {
                "average": sum(event_counts_per_ip.values()) / len(event_counts_per_ip)
                if event_counts_per_ip
                else 0,
                "max": max(event_counts_per_ip.values()) if event_counts_per_ip else 0,
                "min": min(event_counts_per_ip.values()) if event_counts_per_ip else 0,
            },
        }

    def _generate_recommendations(
        self, profiles: dict[str, AttackerProfile]
    ) -> list[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []

        all_attack_types = set()
        for profile in profiles.values():
            all_attack_types.update(profile.attack_types)

        if "sql_injection" in all_attack_types:
            recommendations.append("Implement prepared statements and input validation for SQL queries")

        if "credential_access" in all_attack_types:
            recommendations.append("Enforce strong password policies and implement rate limiting on login attempts")

        if "command_activity" in all_attack_types:
            recommendations.append("Restrict command execution and monitor system command activity")

        if len(profiles) > 10:
            recommendations.append("High volume of attacker activity detected. Review firewall rules and consider additional access controls")

        critical_count = sum(
            p.severity_distribution.get("critical", 0) for p in profiles.values()
        )
        if critical_count > 5:
            recommendations.append("Multiple critical events detected. Immediate investigation and response recommended")

        return recommendations

    def _generate_risk_indicators(self, profile: AttackerProfile) -> list[str]:
        """Generate risk indicators for an attacker"""
        indicators = []

        if "critical" in profile.severity_distribution:
            indicators.append("critical_severity_events")

        if "credential_access" in profile.attack_types:
            indicators.append("credential_compromise_attempt")

        if len(profile.files_accessed) > 0:
            indicators.append("data_exfiltration_detected")

        if len(profile.commands_executed) > 5:
            indicators.append("extensive_command_execution")

        if profile.behavioral_patterns.get("persistence_attempts", 0) > 0:
            indicators.append("persistence_mechanism_detected")

        return indicators

    def send_to_webhook(self, payload: dict[str, Any]) -> bool:
        """
        Send XAI report to n8n webhook

        Args:
            payload: Dictionary to send

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Sending XAI report to webhook: {self.webhook_url}")

            response = self.session.post(
                self.webhook_url,
                json=payload,
                timeout=self.timeout_seconds,
                headers={"Content-Type": "application/json"},
            )

            response.raise_for_status()

            logger.info(
                f"Successfully sent XAI report. Status code: {response.status_code}"
            )
            return True

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error while sending to webhook: {e}")
            return False

        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout while sending to webhook: {e}")
            return False

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            return False

    def process_and_send(self, log_file: Path, webhook_url: Optional[str] = None) -> bool:
        """
        Process events from log file and send to webhook

        Args:
            log_file: Path to JSONL log file
            webhook_url: Override webhook URL (optional)

        Returns:
            True if successful, False otherwise
        """
        if webhook_url:
            self.webhook_url = webhook_url

        try:
            # Load events
            events = self.load_events_from_jsonl(log_file)

            # Process events
            self.process_events(events)

            # Build XAI report
            report = self.build_xai_report()

            logger.info(
                f"Generated XAI report with {report['report_metadata']['total_attackers']} attackers"
            )

            # Send to webhook
            return self.send_to_webhook(report)

        except Exception as e:
            logger.error(f"Error during processing and sending: {e}")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="XAI Merger: Merge attack data and send to n8n webhook"
    )
    parser.add_argument(
        "--webhook-url",
        type=str,
        required=True,
        help="N8n webhook URL",
    )
    parser.add_argument(
        "--log-file",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "data" / "raw_logs" / "honeypot_events.jsonl",
        help="Path to honeypot events JSONL file",
    )
    parser.add_argument(
        "--output-file",
        type=Path,
        help="Path to save XAI report locally (optional)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Generate report but don't send to webhook",
    )

    args = parser.parse_args()

    # Create merger
    merger = XAIMerger(webhook_url=args.webhook_url)

    # Process events
    events = merger.load_events_from_jsonl(args.log_file)
    merger.process_events(events)

    # Build report
    report = merger.build_xai_report()

    # Save locally if requested
    if args.output_file:
        with open(args.output_file, "w") as f:
            json.dump(report, f, indent=2)
        logger.info(f"Saved XAI report to {args.output_file}")

    # Send to webhook unless dry-run
    if not args.dry_run:
        success = merger.send_to_webhook(report)
        exit(0 if success else 1)
    else:
        logger.info("Dry-run mode: Report generated but not sent")
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
