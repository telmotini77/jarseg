"""Safe local integration between JARVIS and the CyberSeg IDS."""

# Keep this package lightweight: importing the HTTP client must not import the
# complete JARVIS agent registry (which would create an import cycle).
from app.cyberseg.client import CyberSegClient, CyberSegClientError
from app.cyberseg.monitor import CyberSegMonitor
from app.cyberseg.network_response import LinuxFirewallBlocker, ServerIntrusionResponder
from app.cyberseg.threat_intelligence import coverage_report, enrich_alerts

__all__ = ["CyberSegClient", "CyberSegClientError", "CyberSegMonitor", "LinuxFirewallBlocker", "ServerIntrusionResponder", "coverage_report", "enrich_alerts"]
