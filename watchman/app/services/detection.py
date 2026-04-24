from collections import defaultdict
from datetime import datetime, timedelta


class SuspiciousDetector:
    """Very lightweight IDS-style heuristics for a beginner-friendly starter."""

    def __init__(self) -> None:
        self.ip_counter: dict[str, list[datetime]] = defaultdict(list)

    def evaluate(self, packet: dict) -> tuple[bool, str]:
        now = datetime.utcnow()
        src_ip = packet.get("src_ip", "")
        protocol = packet.get("protocol", "")
        dst_port = packet.get("dst_port")

        if src_ip:
            self.ip_counter[src_ip].append(now)
            window_start = now - timedelta(seconds=10)
            self.ip_counter[src_ip] = [t for t in self.ip_counter[src_ip] if t >= window_start]
            if len(self.ip_counter[src_ip]) > 100:
                return True, "High packet rate from single source (possible scan/flood)"

        if protocol == "TCP" and dst_port in {22, 23, 3389}:
            return True, "Access attempt to high-value remote access port"

        if protocol == "DNS" and packet.get("length", 0) > 800:
            return True, "Large DNS packet anomaly"

        return False, ""
