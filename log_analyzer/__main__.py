import argparse
import json
import sys

from log_analyzer.analyzer import analyze_file


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a positive integer") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze Apache/Nginx access logs for suspicious activity."
    )
    parser.add_argument("logfile", help="path to an Apache or Nginx access log")
    parser.add_argument(
        "--failed-login-threshold",
        type=positive_int,
        default=5,
        help="failed login attempts from one IP that trigger an alert (default: 5)",
    )
    parser.add_argument(
        "--burst-threshold",
        type=positive_int,
        default=100,
        help="requests from one IP in a window that trigger an alert (default: 100)",
    )
    parser.add_argument(
        "--window-seconds",
        type=positive_int,
        default=60,
        help="request-rate window size in seconds (default: 60)",
    )
    parser.add_argument(
        "--output",
        help="write the JSON report to this file instead of standard output",
    )
    args = parser.parse_args()

    try:
        report = analyze_file(
            args.logfile,
            args.failed_login_threshold,
            args.burst_threshold,
            args.window_seconds,
        )
        rendered = json.dumps(report, indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as output_file:
                output_file.write(rendered + "\n")
        else:
            print(rendered)
    except (OSError, UnicodeError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    sys.exit(main())
