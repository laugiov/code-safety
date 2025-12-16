#!/usr/bin/env python3
"""
VulnShop Taint Analysis Benchmark Runner

This script orchestrates benchmarks for all three taint analysis tools
(Pysa, CodeQL, Semgrep) against the VulnShop application and CVE reproductions.

Usage:
    python run_benchmarks.py [OPTIONS]

Options:
    --tools TOOLS       Comma-separated list of tools (pysa,codeql,semgrep) [default: all]
    --output DIR        Output directory for results [default: ../results]
    --format FORMAT     Output format (json,sarif,csv) [default: json]
    --verbose           Enable verbose output
    --skip-execution    Skip tool execution, use existing results
    --help              Show this help message

Example:
    python run_benchmarks.py --tools pysa,semgrep --verbose
"""

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

# Configuration
SCRIPT_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = SCRIPT_DIR.parent.parent
APP_DIR = PROJECT_ROOT / "vulnerable-app"
ANALYSIS_DIR = PROJECT_ROOT / "analysis"
GROUND_TRUTH_FILE = SCRIPT_DIR.parent / "ground-truth" / "vulnerabilities.json"


@dataclass
class Finding:
    """Represents a single security finding from an analysis tool."""
    tool: str
    rule_id: str
    severity: str
    file: str
    line: int
    message: str
    cwe: Optional[str] = None
    vulnerability_id: Optional[str] = None  # Matched ground truth ID


@dataclass
class BenchmarkResult:
    """Results from running a single tool benchmark."""
    tool: str
    execution_time: float
    total_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    findings: List[Finding]
    detected_vulnerabilities: List[str]
    missed_vulnerabilities: List[str]


@dataclass
class BenchmarkSummary:
    """Summary of all benchmark results."""
    timestamp: str
    duration_seconds: float
    tools_analyzed: List[str]
    ground_truth_count: int
    results: Dict[str, BenchmarkResult]
    comparison_matrix: Dict[str, Dict[str, bool]]


class GroundTruth:
    """Manages ground truth vulnerability data."""

    def __init__(self, filepath: Path):
        self.filepath = filepath
        self.vulnerabilities = {}
        self.load()

    def load(self):
        """Load ground truth from JSON file."""
        with open(self.filepath, 'r') as f:
            data = json.load(f)

        for vuln in data.get('vulnerabilities', []):
            self.vulnerabilities[vuln['id']] = vuln

    def get_expected_detections(self, tool: str) -> Set[str]:
        """Get set of vulnerability IDs expected to be detected by a tool."""
        expected = set()
        for vuln_id, vuln in self.vulnerabilities.items():
            detection = vuln.get('expected_detection', {}).get(tool, False)
            if detection is True:
                expected.add(vuln_id)
        return expected

    def match_finding(self, finding: Finding) -> Optional[str]:
        """Attempt to match a finding to a ground truth vulnerability."""
        file_base = Path(finding.file).name

        for vuln_id, vuln in self.vulnerabilities.items():
            location = vuln.get('location', {})
            vuln_file = location.get('file', '')

            # Check file match
            if file_base in vuln_file or vuln_file in finding.file:
                # Check line range if available
                line_start = location.get('line_start', 0)
                line_end = location.get('line_end', 9999)

                if line_start <= finding.line <= line_end + 20:  # Allow some tolerance
                    # Check CWE match if available
                    if finding.cwe and vuln.get('cwe'):
                        if finding.cwe.replace('CWE-', '') in vuln['cwe']:
                            return vuln_id
                    else:
                        return vuln_id

        return None


class ToolRunner:
    """Base class for running analysis tools."""

    def __init__(self, tool_name: str, verbose: bool = False):
        self.tool_name = tool_name
        self.verbose = verbose

    def run(self) -> List[Finding]:
        """Run the tool and return findings."""
        raise NotImplementedError

    def parse_results(self, results_file: Path) -> List[Finding]:
        """Parse tool output into Finding objects."""
        raise NotImplementedError

    def log(self, message: str):
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(f"[{self.tool_name}] {message}")


class PysaRunner(ToolRunner):
    """Runner for Pysa analysis."""

    def __init__(self, verbose: bool = False):
        super().__init__("pysa", verbose)
        self.results_dir = ANALYSIS_DIR / "pysa" / "results"

    def run(self) -> List[Finding]:
        self.log("Starting Pysa analysis...")
        start_time = time.time()

        script_path = ANALYSIS_DIR / "pysa" / "scripts" / "run_pysa.sh"
        if script_path.exists():
            try:
                result = subprocess.run(
                    ["bash", str(script_path), "--skip-type-check"],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                self.log(f"Pysa completed in {time.time() - start_time:.1f}s")
            except subprocess.TimeoutExpired:
                self.log("Pysa analysis timed out")
                return []
            except FileNotFoundError:
                self.log("Pysa not installed")
                return []

        return self.parse_results(self.results_dir / "pysa_results.json")

    def parse_results(self, results_file: Path) -> List[Finding]:
        findings = []
        if not results_file.exists():
            self.log(f"Results file not found: {results_file}")
            return findings

        try:
            with open(results_file, 'r') as f:
                data = json.load(f)

            for issue in data if isinstance(data, list) else data.get('issues', []):
                findings.append(Finding(
                    tool="pysa",
                    rule_id=str(issue.get('code', 'unknown')),
                    severity=self._map_severity(issue),
                    file=issue.get('path', ''),
                    line=issue.get('line', 0),
                    message=issue.get('description', ''),
                    cwe=self._extract_cwe(issue)
                ))
        except (json.JSONDecodeError, KeyError) as e:
            self.log(f"Error parsing results: {e}")

        return findings

    def _map_severity(self, issue: dict) -> str:
        code = issue.get('code', 0)
        if code in [5001, 5002, 5003, 5007, 5010]:  # SQL, RCE, Cmd, Deser, SSTI
            return "CRITICAL"
        elif code in [5004, 5005, 5006, 5009]:  # Path, SSRF, XSS, XXE
            return "HIGH"
        else:
            return "MEDIUM"

    def _extract_cwe(self, issue: dict) -> Optional[str]:
        code_to_cwe = {
            5001: "CWE-89",
            5002: "CWE-94",
            5003: "CWE-78",
            5004: "CWE-22",
            5005: "CWE-918",
            5006: "CWE-79",
            5007: "CWE-502",
            5008: "CWE-532",
            5009: "CWE-611",
            5010: "CWE-1336",
        }
        return code_to_cwe.get(issue.get('code'))


class CodeQLRunner(ToolRunner):
    """Runner for CodeQL analysis."""

    def __init__(self, verbose: bool = False):
        super().__init__("codeql", verbose)
        self.results_dir = ANALYSIS_DIR / "codeql" / "results"

    def run(self) -> List[Finding]:
        self.log("Starting CodeQL analysis...")
        start_time = time.time()

        script_path = ANALYSIS_DIR / "codeql" / "scripts" / "run_analysis.sh"
        if script_path.exists():
            try:
                result = subprocess.run(
                    ["bash", str(script_path)],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                self.log(f"CodeQL completed in {time.time() - start_time:.1f}s")
            except subprocess.TimeoutExpired:
                self.log("CodeQL analysis timed out")
                return []
            except FileNotFoundError:
                self.log("CodeQL not installed")
                return []

        return self.parse_results(self.results_dir / "codeql_results.sarif")

    def parse_results(self, results_file: Path) -> List[Finding]:
        findings = []
        if not results_file.exists():
            self.log(f"Results file not found: {results_file}")
            return findings

        try:
            with open(results_file, 'r') as f:
                data = json.load(f)

            for run in data.get('runs', []):
                for result in run.get('results', []):
                    location = result.get('locations', [{}])[0]
                    physical = location.get('physicalLocation', {})
                    artifact = physical.get('artifactLocation', {})
                    region = physical.get('region', {})

                    findings.append(Finding(
                        tool="codeql",
                        rule_id=result.get('ruleId', 'unknown'),
                        severity=self._get_severity(result, run),
                        file=artifact.get('uri', ''),
                        line=region.get('startLine', 0),
                        message=result.get('message', {}).get('text', ''),
                        cwe=self._extract_cwe(result, run)
                    ))
        except (json.JSONDecodeError, KeyError) as e:
            self.log(f"Error parsing results: {e}")

        return findings

    def _get_severity(self, result: dict, run: dict) -> str:
        rule_id = result.get('ruleId', '')
        for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
            if rule.get('id') == rule_id:
                severity = rule.get('properties', {}).get('security-severity', '5.0')
                score = float(severity)
                if score >= 9.0:
                    return "CRITICAL"
                elif score >= 7.0:
                    return "HIGH"
                elif score >= 4.0:
                    return "MEDIUM"
                else:
                    return "LOW"
        return "MEDIUM"

    def _extract_cwe(self, result: dict, run: dict) -> Optional[str]:
        rule_id = result.get('ruleId', '')
        for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
            if rule.get('id') == rule_id:
                tags = rule.get('properties', {}).get('tags', [])
                for tag in tags:
                    if tag.startswith('external/cwe/cwe-'):
                        return tag.replace('external/cwe/', '').upper()
        return None


class SemgrepRunner(ToolRunner):
    """Runner for Semgrep analysis."""

    def __init__(self, verbose: bool = False):
        super().__init__("semgrep", verbose)
        self.results_dir = ANALYSIS_DIR / "semgrep" / "results"

    def run(self) -> List[Finding]:
        self.log("Starting Semgrep analysis...")
        start_time = time.time()

        script_path = ANALYSIS_DIR / "semgrep" / "scripts" / "run_semgrep.sh"
        if script_path.exists():
            try:
                result = subprocess.run(
                    ["bash", str(script_path), "--rules-only"],
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                self.log(f"Semgrep completed in {time.time() - start_time:.1f}s")
            except subprocess.TimeoutExpired:
                self.log("Semgrep analysis timed out")
                return []
            except FileNotFoundError:
                self.log("Semgrep not installed")
                return []

        return self.parse_results(self.results_dir / "semgrep_results.json")

    def parse_results(self, results_file: Path) -> List[Finding]:
        findings = []
        if not results_file.exists():
            self.log(f"Results file not found: {results_file}")
            return findings

        try:
            with open(results_file, 'r') as f:
                data = json.load(f)

            for result in data.get('results', []):
                findings.append(Finding(
                    tool="semgrep",
                    rule_id=result.get('check_id', 'unknown'),
                    severity=result.get('extra', {}).get('severity', 'WARNING').upper(),
                    file=result.get('path', ''),
                    line=result.get('start', {}).get('line', 0),
                    message=result.get('extra', {}).get('message', ''),
                    cwe=self._extract_cwe(result)
                ))
        except (json.JSONDecodeError, KeyError) as e:
            self.log(f"Error parsing results: {e}")

        return findings

    def _extract_cwe(self, result: dict) -> Optional[str]:
        metadata = result.get('extra', {}).get('metadata', {})
        cwe = metadata.get('cwe', '')
        if isinstance(cwe, str):
            return cwe
        elif isinstance(cwe, list) and cwe:
            return cwe[0]
        return None


def calculate_metrics(
    findings: List[Finding],
    ground_truth: GroundTruth,
    tool: str
) -> BenchmarkResult:
    """Calculate precision, recall, and F1 score for a tool's findings."""

    # Match findings to ground truth
    detected = set()
    for finding in findings:
        vuln_id = ground_truth.match_finding(finding)
        if vuln_id:
            finding.vulnerability_id = vuln_id
            detected.add(vuln_id)

    expected = ground_truth.get_expected_detections(tool)
    all_vulns = set(ground_truth.vulnerabilities.keys())

    true_positives = len(detected & expected)
    false_positives = len(detected - expected)  # Detected but not expected
    false_negatives = len(expected - detected)  # Expected but not detected

    # Calculate metrics
    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return BenchmarkResult(
        tool=tool,
        execution_time=0.0,  # Set by caller
        total_findings=len(findings),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        findings=findings,
        detected_vulnerabilities=list(detected),
        missed_vulnerabilities=list(expected - detected)
    )


def run_benchmark(
    tools: List[str],
    output_dir: Path,
    verbose: bool = False,
    skip_execution: bool = False
) -> BenchmarkSummary:
    """Run complete benchmark suite."""

    print("=" * 60)
    print("VulnShop Taint Analysis Benchmark")
    print("=" * 60)

    start_time = time.time()

    # Load ground truth
    print(f"\nLoading ground truth from: {GROUND_TRUTH_FILE}")
    ground_truth = GroundTruth(GROUND_TRUTH_FILE)
    print(f"Found {len(ground_truth.vulnerabilities)} documented vulnerabilities")

    # Initialize runners
    runners = {
        'pysa': PysaRunner(verbose),
        'codeql': CodeQLRunner(verbose),
        'semgrep': SemgrepRunner(verbose),
    }

    results = {}

    for tool in tools:
        if tool not in runners:
            print(f"Unknown tool: {tool}")
            continue

        print(f"\n--- Running {tool.upper()} ---")
        runner = runners[tool]

        tool_start = time.time()

        if skip_execution:
            print(f"Skipping execution, parsing existing results...")
            # Determine results file path based on tool
            if tool == 'pysa':
                results_file = ANALYSIS_DIR / "pysa" / "results" / "pysa_results.json"
            elif tool == 'codeql':
                results_file = ANALYSIS_DIR / "codeql" / "results" / "codeql_results.sarif"
            else:
                results_file = ANALYSIS_DIR / "semgrep" / "results" / "semgrep_results.json"
            findings = runner.parse_results(results_file)
        else:
            findings = runner.run()

        tool_time = time.time() - tool_start

        result = calculate_metrics(findings, ground_truth, tool)
        result.execution_time = round(tool_time, 2)
        results[tool] = result

        print(f"  Findings: {result.total_findings}")
        print(f"  True Positives: {result.true_positives}")
        print(f"  Precision: {result.precision:.2%}")
        print(f"  Recall: {result.recall:.2%}")
        print(f"  F1 Score: {result.f1_score:.2%}")
        print(f"  Time: {result.execution_time}s")

    # Build comparison matrix
    comparison = {}
    for vuln_id in ground_truth.vulnerabilities:
        comparison[vuln_id] = {}
        for tool in tools:
            if tool in results:
                comparison[vuln_id][tool] = vuln_id in results[tool].detected_vulnerabilities

    total_time = time.time() - start_time

    summary = BenchmarkSummary(
        timestamp=datetime.now().isoformat(),
        duration_seconds=round(total_time, 2),
        tools_analyzed=tools,
        ground_truth_count=len(ground_truth.vulnerabilities),
        results={k: asdict(v) for k, v in results.items()},
        comparison_matrix=comparison
    )

    # Save results
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / "benchmark_results.json"

    with open(output_file, 'w') as f:
        json.dump(asdict(summary), f, indent=2, default=str)

    print(f"\n{'=' * 60}")
    print(f"Benchmark complete! Results saved to: {output_file}")
    print(f"Total time: {total_time:.1f}s")
    print(f"{'=' * 60}")

    return summary


def main():
    parser = argparse.ArgumentParser(description="VulnShop Taint Analysis Benchmark Runner")
    parser.add_argument('--tools', type=str, default='pysa,codeql,semgrep',
                        help='Comma-separated list of tools')
    parser.add_argument('--output', type=str, default=str(SCRIPT_DIR.parent / "results"),
                        help='Output directory')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--skip-execution', action='store_true',
                        help='Use existing results')

    args = parser.parse_args()

    tools = [t.strip().lower() for t in args.tools.split(',')]
    output_dir = Path(args.output)

    run_benchmark(
        tools=tools,
        output_dir=output_dir,
        verbose=args.verbose,
        skip_execution=args.skip_execution
    )


if __name__ == '__main__':
    main()
