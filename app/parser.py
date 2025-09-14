import re
from datetime import datetime
from typing import Iterator, Optional
from collections import deque
from .models import LogEvent

# Suricata fast.log line patterns (simplified)
# Example: 03/16/2012-12:30:00.090000  [**] [1:2024364:5] ET SCAN Possible Nmap User-Agent Observed [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.202.79:50477 -> 192.168.229.251:80
FAST_LOG_REGEX = re.compile(r"""
^(?P<ts>\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d{6})\s+\[\*\*]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)]\s+(?P<signature>.*?)\s+\[\*\*]\s+\[Classification:\s*(?P<classification>[^\]]+)\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+(?:\{(?P<protocol>[^}]+)\}\s+(?P<src>\S+)\s+->\s+(?P<dst>\S+))?
""", re.VERBOSE)

# Some lines (e.g., Ethertype unknown) might not have IP:port pairs; handle gracefully.

def parse_fast_log(path: str, max_lines: Optional[int] = 20000) -> Iterator[LogEvent]:
    """Parse Suricata fast.log.

    Parameters
    ----------
    path : str
        Path to fast.log
    max_lines : Optional[int]
        If provided, only keep the last N lines in memory to reduce startup cost on huge files.
    """
    if max_lines is not None and max_lines > 0:
        # Keep only last max_lines lines (memory efficient deque)
        dq = deque(maxlen=max_lines)
        with open(path, 'r', errors='ignore') as f:
            for line in f:
                dq.append(line)
        iterable = dq
    else:
        with open(path, 'r', errors='ignore') as f:
            iterable = list(f)

    for raw in iterable:
        line = raw.strip()
        if not line:
            continue
        m = FAST_LOG_REGEX.match(line)
        if not m:
            continue
        gd = m.groupdict()
        try:
            ts = datetime.strptime(gd['ts'], '%m/%d/%Y-%H:%M:%S.%f')
        except Exception:
            continue
        src_ip = src_port = dst_ip = dst_port = None
        if gd.get('src') and gd.get('dst') and ':' in gd['src'] and ':' in gd['dst']:
            try:
                src_ip, src_port = gd['src'].rsplit(':', 1)
                dst_ip, dst_port = gd['dst'].rsplit(':', 1)
                src_port = int(src_port)
                dst_port = int(dst_port)
            except ValueError:
                pass
        yield LogEvent(
            timestamp=ts,
            gid=gd.get('gid'),
            sid=gd.get('sid'),
            rev=gd.get('rev'),
            signature=gd.get('signature','').strip(),
            classification=gd.get('classification'),
            priority=int(gd['priority']) if gd.get('priority') else None,
            protocol=gd.get('protocol'),
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
        )
