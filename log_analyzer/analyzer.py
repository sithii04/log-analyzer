from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) \S+'
)
LOGIN_PATH_PATTERN = re.compile(r"/(?:login|signin|sign-in|auth)(?:/|$)", re.IGNORECASE)


def parse_log_line(line: str) -> dict[str, Any] | None:
    """Parse one Apache/Nginx combined or common access-log line."""
    match = LOG_PATTERN.match(line)
    if match is None:
        return None

    try:
        timestamp = datetime.strptime(
            match.group("timestamp"), "%d/%b/%Y:%H:%M:%S %z"
        ).astimezone(timezone.utc)
    except ValueError:
        return None

    request_parts = match.group("request").split()
    if len(request_parts) < 2:
        return None

    method, path = request_parts[:2]
    return {
        "ip": match.group("ip"),
        "timestamp": timestamp,
        "method": method,
        "path": path.split("?", 1)[0],
        "status": int(match.group("status")),
    }


def analyze_lines(
    lines: list[str],
    failed_login_threshold: int = 5,
    burst_threshold: int = 100,
    window_seconds: int = 60,
) -> dict[str, Any]:
    if failed_login_threshold < 1 or burst_threshold < 1 or window_seconds < 1:
        raise ValueError("Thresholds and window size must be greater than zero.")

    request_counts: Counter[str] = Counter()
    failed_logins: Counter[str] = Counter()
    request_timestamps: dict[str, list[int]] = defaultdict(list)
    malformed_line_numbers: list[int] = []
    parsed_lines = 0

    for line_number, line in enumerate(lines, start=1):
        record = parse_log_line(line.rstrip("\r\n"))
        if record is None:
            malformed_line_numbers.append(line_number)
            continue

        parsed_lines += 1
        ip = record["ip"]
        request_counts[ip] += 1
        request_timestamps[ip].append(int(record["timestamp"].timestamp()))

        if (
            record["method"].upper() == "POST"
            and LOGIN_PATH_PATTERN.search(record["path"])
            and record["status"] >= 400
        ):
            failed_logins[ip] += 1

    suspicious_ips = []
    for ip in sorted(request_counts):
        timestamps = sorted(request_timestamps[ip])
        window_start = 0
        peak_end = timestamps[0]
        peak_count = 0
        for window_end, timestamp in enumerate(timestamps):
            while timestamp - timestamps[window_start] > window_seconds:
                window_start += 1
            current_count = window_end - window_start + 1
            if current_count > peak_count:
                peak_count = current_count
                peak_end = timestamp

        reasons = []
        if failed_logins[ip] >= failed_login_threshold:
            reasons.append("repeated_failed_logins")
        if peak_count >= burst_threshold:
            reasons.append("high_request_rate")

        if reasons:
            peak_end_time = datetime.fromtimestamp(peak_end, tz=timezone.utc)
            suspicious_ips.append(
                {
                    "ip": ip,
                    "reasons": reasons,
                    "failed_login_attempts": failed_logins[ip],
                    "requests_in_peak_window": peak_count,
                    "peak_window_end": peak_end_time.isoformat(),
                }
            )

    return {
        "summary": {
            "total_lines": len(lines),
            "parsed_lines": parsed_lines,
            "malformed_lines": len(malformed_line_numbers),
            "failed_login_attempts": sum(failed_logins.values()),
            "suspicious_ip_count": len(suspicious_ips),
        },
        "failed_logins_by_ip": dict(sorted(failed_logins.items())),
        "suspicious_ips": suspicious_ips,
        "malformed_line_numbers": malformed_line_numbers,
        "thresholds": {
            "failed_login_threshold": failed_login_threshold,
            "burst_threshold": burst_threshold,
            "window_seconds": window_seconds,
        },
    }


def analyze_file(
    path: str | Path,
    failed_login_threshold: int = 5,
    burst_threshold: int = 100,
    window_seconds: int = 60,
) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as log_file:
        lines = log_file.readlines()
    return analyze_lines(lines, failed_login_threshold, burst_threshold, window_seconds)
