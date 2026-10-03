import unittest

from log_analyzer.analyzer import analyze_lines, parse_log_line


class ParseLogLineTests(unittest.TestCase):
    def test_parses_combined_access_log(self):
        record = parse_log_line(
            '203.0.113.10 - - [03/Oct/2026:12:00:00 +0000] '
            '"POST /login HTTP/1.1" 401 123 "-" "test-agent"'
        )

        self.assertIsNotNone(record)
        self.assertEqual(record["ip"], "203.0.113.10")
        self.assertEqual(record["method"], "POST")
        self.assertEqual(record["path"], "/login")
        self.assertEqual(record["status"], 401)

    def test_rejects_malformed_line(self):
        self.assertIsNone(parse_log_line("not an access log"))


class AnalyzeLinesTests(unittest.TestCase):
    def test_identifies_repeated_failed_logins_and_bursts(self):
        lines = [
            f'203.0.113.10 - - [03/Oct/2026:12:00:{second:02d} +0000] '
            '"POST /api/auth/login HTTP/1.1" 401 10'
            for second in range(5)
        ]

        report = analyze_lines(
            lines,
            failed_login_threshold=5,
            burst_threshold=5,
            window_seconds=60,
        )

        self.assertEqual(report["summary"]["failed_login_attempts"], 5)
        self.assertEqual(report["summary"]["suspicious_ip_count"], 1)
        self.assertEqual(
            report["suspicious_ips"][0]["reasons"],
            ["repeated_failed_logins", "high_request_rate"],
        )

    def test_reports_malformed_lines_without_exposing_log_contents(self):
        report = analyze_lines(["secret malformed log content"])

        self.assertEqual(report["summary"]["malformed_lines"], 1)
        self.assertEqual(report["malformed_line_numbers"], [1])

    def test_detects_requests_across_a_minute_boundary(self):
        lines = [
            '203.0.113.10 - - [03/Oct/2026:12:00:59 +0000] "GET / HTTP/1.1" 200 10',
            '203.0.113.10 - - [03/Oct/2026:12:01:00 +0000] "GET / HTTP/1.1" 200 10',
        ]

        report = analyze_lines(
            lines, failed_login_threshold=5, burst_threshold=2, window_seconds=60
        )

        self.assertEqual(report["suspicious_ips"][0]["requests_in_peak_window"], 2)

    def test_rejects_non_positive_threshold(self):
        with self.assertRaises(ValueError):
            analyze_lines([], burst_threshold=0)


if __name__ == "__main__":
    unittest.main()
