# AWS IAM Security Analyzer

A Python-based AWS IAM Security Analyzer that audits IAM users, groups, and roles to detect common security misconfigurations and privilege escalation risks.

## Features

- Detects wildcard (`*`) permissions
- Detects wildcard resource access
- Identifies common IAM privilege escalation paths
- Checks access key age (90+ days)
- Scans IAM Users, Groups, and Roles
- Generates JSON, HTML, and PDF security audit reports
- Read-only analysis (does not modify AWS resources)

## Technologies

- Python
- AWS IAM
- Boto3
- ReportLab
- JSON
- HTML

## Installation

```bash
pip install boto3 reportlab pytz
```

## Usage

```bash
python iam_security_analyzer.py
```

## Output

The tool generates:

- findings.json
- IAM_Report.html
- IAM_Report.pdf

## Security Checks

- Wildcard IAM Actions
- Wildcard Resources
- Privilege Escalation Detection
- Old Access Keys
- IAM Policy Analysis

## Project Structure

```
aws-iam-security-analyzer/
│
├── iam_security_analyzer.py
├── findings.json
├── IAM_Report.html
├── IAM_Report.pdf
└── README.md
```

## Disclaimer

This tool performs read-only security analysis and does not make any changes to AWS resources.
