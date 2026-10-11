import time

class RuleBasedDetector:
    def __init__(self, baseline_ip_prefix="192.168.1.", baseline_ua=None, allowed_endpoints=None):
        self.baseline_ip_prefix = baseline_ip_prefix
        self.baseline_ua = baseline_ua or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/128.0.0.0"
        self.allowed_endpoints = allowed_endpoints or ["/dashboard", "/profile", "/settings", "/logout"]

    def evaluate(self, ip: str, user_agent: str, endpoint: str):
        start_time = time.perf_counter()
        violations = []

        # Rule 1: Subnet Verification
        if not ip.startswith(self.baseline_ip_prefix):
            violations.append("Subnet mismatch: IP does not belong to authorized network")

        # Rule 2: User-Agent Fingerprint Check
        if user_agent != self.baseline_ua:
            violations.append("Header mismatch: Client User-Agent string altered")

        # Rule 3: Known Endpoint Whitelist Check
        if endpoint not in self.allowed_endpoints:
            violations.append(f"Privilege violation: Access to unauthorized route '{endpoint}'")

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        is_hijacked = len(violations) > 0

        return {
            "status": "HIJACK DETECTED" if is_hijacked else "NORMAL",
            "is_hijacked": is_hijacked,
            "violations": violations,
            "latency_ms": latency_ms,
            "action": "Terminate Session Immediately" if is_hijacked else "Allow Request"
        }