# Log Analyzer

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg)

A dependency-free Python command-line tool that analyzes Apache/Nginx access logs for repeated failed logins and unusually high per-IP request rates.

## Features

- Parses Apache/Nginx common and combined access-log lines.
- Counts failed `POST` requests to login/authentication endpoints by IP.
- Flags repeated failed logins and high request rates within configurable time windows.
- Produces a JSON report and records malformed line numbers without copying log contents.
- Includes sample input and unit tests.

## Requirements

- Python 3.10 or newer
- No third-party packages

## Run locally

```powershell
git clone https://github.com/YOUR-USERNAME/log-analyzer.git
cd log-analyzer
python -m log_analyzer samples/access.log
```

To save the report to a file:

```powershell
python -m log_analyzer samples/access.log --output report.json
```

Customize alert thresholds (defaults: 5 failed logins, 100 requests per 60 seconds):

```powershell
python -m log_analyzer access.log --failed-login-threshold 3 --burst-threshold 50 --window-seconds 30
```

Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

## GitHub setup and commit history

Create an empty repository on GitHub (do not add a README there), then run these commands from this project directory:

```powershell
git init
git add README.md .gitignore
git commit -m "docs: add project overview and usage instructions"
git add log_analyzer
git commit -m "feat: parse access logs and detect suspicious activity"
git add tests samples
git commit -m "test: add sample logs and analyzer coverage"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/log-analyzer.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username. Keep real production logs out of GitHub; logs can contain personal data, tokens, or other sensitive information.

## Detection notes

- A failed login is a `POST` request whose path contains a login/authentication endpoint (`login`, `signin`, `sign-in`, or `auth`) and whose status is `400` or higher.
- The request-rate check uses a sliding time window per IP. It is a simple triage signal, not proof of a DDoS attack.
- Tune thresholds for your traffic. NAT gateways and shared proxies can make many legitimate users appear under one IP.

## License

This project is licensed under the MIT License.
