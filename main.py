"""Log Analyzer Tool - Parse and analyze log files with pattern matching."""
import re
from collections import Counter
from pathlib import Path
from datetime import datetime

LOG_PATTERN = re.compile(
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<date>\[.+?\])\s+"
    r'(?P<method>GET|POST|PUT|DELETE|PATCH)\s+(?P<path>/\S*)\s+HTTP/\S+'
    r'\s+"\s*(?P<status>\d{3})\s+(?P<size>\d+|-)',
    re.IGNORECASE
)

SAMPLE_LOG = """192.168.1.1 [24/Feb/2026:08:00:01] "GET /index.html HTTP/1.1" 200 4523
10.0.0.2 [24/Feb/2026:08:00:05] "POST /api/login HTTP/1.1" 401 89
192.168.1.3 [24/Feb/2026:08:00:10] "GET /dashboard HTTP/1.1" 200 12300
10.0.0.5 [24/Feb/2026:08:00:15] "GET /api/data HTTP/1.1" 500 0
192.168.1.1 [24/Feb/2026:08:00:20] "DELETE /api/user/5 HTTP/1.1" 403 0
10.0.0.2 [24/Feb/2026:08:00:25] "GET /index.html HTTP/1.1" 200 4523
"""

def analyze(log_text):
    matches = LOG_PATTERN.findall(log_text)
    if not matches:
        print("No log entries found."); return
    ips = Counter(m[0] for m in matches)
    statuses = Counter(m[4] for m in matches)
    paths = Counter(m[3] for m in matches)
    methods = Counter(m[2] for m in matches)
    errors = [m for m in matches if m[4].startswith(("4","5"))]

    print("\n📊 Log Analysis Report")
    print("=" * 45)
    print(f"Total Requests : {len(matches)}")
    print(f"Unique IPs     : {len(ips)}")
    print("\nTop IPs:")
    for ip, cnt in ips.most_common(3):
        print(f"  {ip:<18} {cnt} requests")
    print("\nStatus Codes:")
    for code, cnt in sorted(statuses.items()):
        print(f"  HTTP {code}: {cnt}")
    print("\nHTTP Methods:")
    for m, cnt in methods.items():
        print(f"  {m:<8} {cnt}")
    if errors:
        print(f"\n⚠️  Errors ({len(errors)}):")
        for e in errors:
            print(f"  {e[0]} -> {e[2]} {e[3]} [{e[4]}]")

if __name__ == "__main__":
    analyze(SAMPLE_LOG)
