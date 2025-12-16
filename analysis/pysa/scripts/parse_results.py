#!/usr/bin/env python3
"""
Pysa Results Parser and SARIF Converter

This script parses Pysa JSON output and converts it to SARIF format
for integration with GitHub Security tab and other security tools.

Usage:
    python parse_results.py --input results.json --output results.sarif

SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for representing static analysis results.

Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


# Rule definitions mapping Pysa codes to security metadata
RULE_DEFINITIONS = {
    5001: {
        "id": "pysa/sql-injection",
        "name": "SQL Injection",
        "shortDescription": "SQL Injection vulnerability detected",
        "fullDescription": "User-controlled data flows to SQL query execution without proper sanitization, potentially allowing attackers to execute arbitrary SQL commands.",
        "helpUri": "https://owasp.org/www-community/attacks/SQL_Injection",
        "security-severity": "9.8",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-89", "external/owasp/owasp-a03"],
    },
    5002: {
        "id": "pysa/remote-code-execution",
        "name": "Remote Code Execution",
        "shortDescription": "Remote code execution vulnerability detected",
        "fullDescription": "Untrusted data flows to code execution functions, potentially allowing attackers to execute arbitrary code on the server.",
        "helpUri": "https://owasp.org/www-community/attacks/Code_Injection",
        "security-severity": "10.0",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-94", "external/owasp/owasp-a03"],
    },
    5003: {
        "id": "pysa/command-injection",
        "name": "Command Injection",
        "shortDescription": "OS command injection vulnerability detected",
        "fullDescription": "User-controlled data flows to OS command execution without proper sanitization, potentially allowing attackers to execute arbitrary system commands.",
        "helpUri": "https://owasp.org/www-community/attacks/Command_Injection",
        "security-severity": "9.8",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-78", "external/owasp/owasp-a03"],
    },
    5004: {
        "id": "pysa/path-traversal",
        "name": "Path Traversal",
        "shortDescription": "Path traversal vulnerability detected",
        "fullDescription": "User-controlled data is used in file path operations without validation, potentially allowing attackers to access files outside the intended directory.",
        "helpUri": "https://owasp.org/www-community/attacks/Path_Traversal",
        "security-severity": "7.5",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-22", "external/owasp/owasp-a01"],
    },
    5005: {
        "id": "pysa/ssrf",
        "name": "Server-Side Request Forgery",
        "shortDescription": "SSRF vulnerability detected",
        "fullDescription": "User-controlled URL flows to HTTP request functions, potentially allowing attackers to make requests to internal services or external systems.",
        "helpUri": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        "security-severity": "9.1",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-918", "external/owasp/owasp-a10"],
    },
    5006: {
        "id": "pysa/xss",
        "name": "Cross-Site Scripting",
        "shortDescription": "XSS vulnerability detected",
        "fullDescription": "Untrusted data is rendered in HTML without proper escaping, potentially allowing attackers to inject malicious scripts.",
        "helpUri": "https://owasp.org/www-community/attacks/xss/",
        "security-severity": "6.1",
        "precision": "medium",
        "tags": ["security", "external/cwe/cwe-79", "external/owasp/owasp-a03"],
    },
    5007: {
        "id": "pysa/insecure-deserialization",
        "name": "Insecure Deserialization",
        "shortDescription": "Insecure deserialization vulnerability detected",
        "fullDescription": "Untrusted data is deserialized using unsafe methods like pickle, potentially allowing remote code execution.",
        "helpUri": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests",
        "security-severity": "9.8",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-502", "external/owasp/owasp-a08"],
    },
    5008: {
        "id": "pysa/sensitive-data-logging",
        "name": "Sensitive Data Logging",
        "shortDescription": "Sensitive data may be logged",
        "fullDescription": "Potentially sensitive user data flows to logging functions, which may expose credentials or personal information in log files.",
        "helpUri": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Session_Tokens_Leaked_in_Log_Files",
        "security-severity": "5.5",
        "precision": "medium",
        "tags": ["security", "external/cwe/cwe-532", "external/owasp/owasp-a09"],
    },
    5009: {
        "id": "pysa/xxe",
        "name": "XML External Entity Injection",
        "shortDescription": "XXE vulnerability detected",
        "fullDescription": "User-controlled XML data is parsed without disabling external entities, potentially allowing file disclosure or SSRF attacks.",
        "helpUri": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        "security-severity": "7.5",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-611", "external/owasp/owasp-a05"],
    },
    5010: {
        "id": "pysa/ssti",
        "name": "Server-Side Template Injection",
        "shortDescription": "SSTI vulnerability detected",
        "fullDescription": "User-controlled data is used in template construction, potentially allowing attackers to execute arbitrary code through template expressions.",
        "helpUri": "https://portswigger.net/web-security/server-side-template-injection",
        "security-severity": "9.8",
        "precision": "high",
        "tags": ["security", "external/cwe/cwe-1336", "external/owasp/owasp-a03"],
    },
    5011: {
        "id": "pysa/open-redirect",
        "name": "Open Redirect",
        "shortDescription": "Open redirect vulnerability detected",
        "fullDescription": "User-controlled data is used in redirect URLs without validation, potentially allowing phishing attacks.",
        "helpUri": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        "security-severity": "4.7",
        "precision": "medium",
        "tags": ["security", "external/cwe/cwe-601", "external/owasp/owasp-a01"],
    },
}


@dataclass
class PysaFinding:
    """Represents a single Pysa finding."""
    code: int
    name: str
    message: str
    filename: str
    line: int
    column: int
    sink_line: Optional[int]
    sink_column: Optional[int]
    trace: List[Dict[str, Any]]


def parse_pysa_results(input_file: str) -> List[PysaFinding]:
    """
    Parse Pysa JSON results file.

    Args:
        input_file: Path to Pysa JSON results

    Returns:
        List of PysaFinding objects
    """
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    findings = []

    for item in data:
        # Extract basic info
        code = item.get('code', 0)
        name = item.get('name', 'Unknown')
        message = item.get('description', item.get('message', 'No description'))

        # Extract location info
        location = item.get('location', {})
        filename = location.get('path', 'unknown')
        line = location.get('line', 1)
        column = location.get('column', 1)

        # Extract sink location if available
        sink = item.get('sink', {})
        sink_line = sink.get('line')
        sink_column = sink.get('column')

        # Extract trace information
        trace = item.get('trace', [])

        findings.append(PysaFinding(
            code=code,
            name=name,
            message=message,
            filename=filename,
            line=line,
            column=column,
            sink_line=sink_line,
            sink_column=sink_column,
            trace=trace
        ))

    return findings


def get_rule_definition(code: int) -> Dict[str, Any]:
    """
    Get rule definition for a Pysa error code.

    Args:
        code: Pysa error code

    Returns:
        Rule definition dictionary
    """
    if code in RULE_DEFINITIONS:
        return RULE_DEFINITIONS[code]

    # Return generic definition for unknown codes
    return {
        "id": f"pysa/rule-{code}",
        "name": f"Pysa Rule {code}",
        "shortDescription": f"Pysa finding (code {code})",
        "fullDescription": "A potential security issue was detected by Pysa taint analysis.",
        "helpUri": "https://pyre-check.org/docs/pysa-basics/",
        "security-severity": "5.0",
        "precision": "medium",
        "tags": ["security"],
    }


def create_sarif_result(finding: PysaFinding, base_path: str) -> Dict[str, Any]:
    """
    Create a SARIF result object from a Pysa finding.

    Args:
        finding: PysaFinding object
        base_path: Base path for relative file paths

    Returns:
        SARIF result dictionary
    """
    rule_def = get_rule_definition(finding.code)

    # Build location
    artifact_location = {
        "uri": finding.filename,
        "uriBaseId": "%SRCROOT%"
    }

    region = {
        "startLine": finding.line,
        "startColumn": finding.column
    }

    # Add sink location if available
    related_locations = []
    if finding.sink_line:
        related_locations.append({
            "id": 1,
            "message": {"text": "Taint sink location"},
            "physicalLocation": {
                "artifactLocation": artifact_location,
                "region": {
                    "startLine": finding.sink_line,
                    "startColumn": finding.sink_column or 1
                }
            }
        })

    result = {
        "ruleId": rule_def["id"],
        "ruleIndex": list(RULE_DEFINITIONS.keys()).index(finding.code) if finding.code in RULE_DEFINITIONS else 0,
        "level": "error" if float(rule_def.get("security-severity", "5.0")) >= 7.0 else "warning",
        "message": {
            "text": finding.message
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": artifact_location,
                    "region": region
                }
            }
        ]
    }

    if related_locations:
        result["relatedLocations"] = related_locations

    # Add code flows for trace information
    if finding.trace:
        code_flows = []
        thread_flows = []

        for i, trace_item in enumerate(finding.trace):
            trace_location = trace_item.get('location', {})
            thread_flows.append({
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": trace_location.get('path', finding.filename),
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": trace_location.get('line', 1),
                            "startColumn": trace_location.get('column', 1)
                        }
                    },
                    "message": {
                        "text": trace_item.get('kind', f'Step {i + 1}')
                    }
                }
            })

        if thread_flows:
            code_flows.append({
                "threadFlows": [{"locations": thread_flows}]
            })
            result["codeFlows"] = code_flows

    return result


def create_sarif_report(findings: List[PysaFinding], base_path: str) -> Dict[str, Any]:
    """
    Create a complete SARIF report from Pysa findings.

    Args:
        findings: List of PysaFinding objects
        base_path: Base path for relative file paths

    Returns:
        SARIF report dictionary
    """
    # Build rules array from unique findings
    seen_codes = set()
    rules = []

    for finding in findings:
        if finding.code not in seen_codes:
            seen_codes.add(finding.code)
            rule_def = get_rule_definition(finding.code)
            rules.append({
                "id": rule_def["id"],
                "name": rule_def["name"],
                "shortDescription": {"text": rule_def["shortDescription"]},
                "fullDescription": {"text": rule_def["fullDescription"]},
                "helpUri": rule_def["helpUri"],
                "properties": {
                    "security-severity": rule_def["security-severity"],
                    "precision": rule_def["precision"],
                    "tags": rule_def["tags"]
                }
            })

    # Build results array
    results = [create_sarif_result(f, base_path) for f in findings]

    # Create SARIF document
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Pysa",
                        "organization": "Meta",
                        "version": "1.0.0",
                        "informationUri": "https://pyre-check.org/docs/pysa-basics/",
                        "rules": rules,
                        "properties": {
                            "tags": ["security", "taint-analysis", "python"]
                        }
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.utcnow().isoformat() + "Z"
                    }
                ],
                "originalUriBaseIds": {
                    "%SRCROOT%": {
                        "uri": f"file://{base_path}/"
                    }
                }
            }
        ]
    }

    return sarif


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Convert Pysa JSON results to SARIF format"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Input Pysa JSON results file"
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output SARIF file"
    )
    parser.add_argument(
        "--base-path",
        default="",
        help="Base path for relative file URIs"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output"
    )

    args = parser.parse_args()

    # Check input file exists
    if not Path(args.input).exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    # Parse Pysa results
    print(f"Parsing Pysa results from: {args.input}")
    findings = parse_pysa_results(args.input)
    print(f"Found {len(findings)} findings")

    # Determine base path
    base_path = args.base_path or str(Path(args.input).parent.parent.parent / "vulnerable-app")

    # Create SARIF report
    print("Converting to SARIF format...")
    sarif = create_sarif_report(findings, base_path)

    # Write output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        if args.pretty:
            json.dump(sarif, f, indent=2)
        else:
            json.dump(sarif, f)

    print(f"SARIF report written to: {args.output}")

    # Print summary
    print("\nSummary:")
    print(f"  Total findings: {len(findings)}")
    print(f"  Unique rules: {len(sarif['runs'][0]['tool']['driver']['rules'])}")

    # Count by severity
    error_count = sum(1 for r in sarif['runs'][0]['results'] if r['level'] == 'error')
    warning_count = sum(1 for r in sarif['runs'][0]['results'] if r['level'] == 'warning')
    print(f"  Errors: {error_count}")
    print(f"  Warnings: {warning_count}")


if __name__ == "__main__":
    main()
