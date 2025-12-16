#!/usr/bin/env python3
"""
Benchmark Report Generator

Generates comprehensive benchmark reports in multiple formats:
- Markdown report with tables and analysis
- HTML report with charts (requires matplotlib)
- CSV data export for further analysis

Usage:
    python generate_report.py [OPTIONS]

Options:
    --input FILE        Input benchmark results JSON [default: ../results/benchmark_results.json]
    --output DIR        Output directory for reports [default: ../reports]
    --format FORMAT     Output format (markdown,html,csv,all) [default: all]
    --include-charts    Generate chart images (requires matplotlib)
    --help              Show this help message
"""

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_INPUT = SCRIPT_DIR.parent / "results" / "benchmark_results.json"
DEFAULT_OUTPUT = SCRIPT_DIR.parent / "reports"


@dataclass
class ToolMetrics:
    """Metrics for a single tool."""
    tool: str
    total_findings: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    execution_time: float
    detected: List[str]
    missed: List[str]


def load_results(filepath: Path) -> Dict[str, Any]:
    """Load benchmark results from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def generate_markdown_report(data: Dict[str, Any], output_dir: Path) -> Path:
    """Generate a comprehensive Markdown report."""

    output_file = output_dir / "benchmark_report.md"

    tools = data.get('tools_analyzed', [])
    results = data.get('results', {})
    comparison = data.get('comparison_matrix', {})

    # Start building report
    lines = []

    # Header
    lines.append("# VulnShop Taint Analysis Benchmark Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Benchmark Run:** {data.get('timestamp', 'Unknown')}")
    lines.append(f"**Total Duration:** {data.get('duration_seconds', 0):.1f} seconds")
    lines.append("")

    # Executive Summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append("This report presents a comparative analysis of three leading static application ")
    lines.append("security testing (SAST) tools using taint analysis against the VulnShop ")
    lines.append(f"vulnerable Django application containing {data.get('ground_truth_count', 16)} documented vulnerabilities.")
    lines.append("")

    # Summary Table
    lines.append("### Overall Performance")
    lines.append("")
    lines.append("| Metric | " + " | ".join(t.upper() for t in tools) + " |")
    lines.append("|--------|" + "|".join(["--------"] * len(tools)) + "|")

    metrics = ['total_findings', 'true_positives', 'precision', 'recall', 'f1_score', 'execution_time']
    metric_labels = {
        'total_findings': 'Total Findings',
        'true_positives': 'True Positives',
        'precision': 'Precision',
        'recall': 'Recall',
        'f1_score': 'F1 Score',
        'execution_time': 'Execution Time'
    }

    for metric in metrics:
        row = [metric_labels[metric]]
        for tool in tools:
            if tool in results:
                value = results[tool].get(metric, 0)
                if metric in ['precision', 'recall', 'f1_score']:
                    row.append(f"{value:.1%}")
                elif metric == 'execution_time':
                    row.append(f"{value:.1f}s")
                else:
                    row.append(str(value))
            else:
                row.append("-")
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")

    # Winner Analysis
    lines.append("### Key Findings")
    lines.append("")

    # Find best tool by F1 score
    best_f1 = max(results.items(), key=lambda x: x[1].get('f1_score', 0))
    best_precision = max(results.items(), key=lambda x: x[1].get('precision', 0))
    best_recall = max(results.items(), key=lambda x: x[1].get('recall', 0))
    fastest = min(results.items(), key=lambda x: x[1].get('execution_time', float('inf')))

    lines.append(f"- **Best Overall (F1):** {best_f1[0].upper()} ({best_f1[1].get('f1_score', 0):.1%})")
    lines.append(f"- **Best Precision:** {best_precision[0].upper()} ({best_precision[1].get('precision', 0):.1%})")
    lines.append(f"- **Best Recall:** {best_recall[0].upper()} ({best_recall[1].get('recall', 0):.1%})")
    lines.append(f"- **Fastest:** {fastest[0].upper()} ({fastest[1].get('execution_time', 0):.1f}s)")
    lines.append("")

    # Detection Matrix
    lines.append("## Detection Matrix")
    lines.append("")
    lines.append("Vulnerability detection comparison across all tools:")
    lines.append("")

    header = "| Vulnerability | " + " | ".join(t.upper() for t in tools) + " |"
    separator = "|--------------|" + "|".join([":-:"] * len(tools)) + "|"
    lines.append(header)
    lines.append(separator)

    for vuln_id, detections in sorted(comparison.items()):
        row = [vuln_id]
        for tool in tools:
            detected = detections.get(tool, False)
            row.append("✅" if detected else "❌")
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")

    # Detailed Tool Analysis
    lines.append("## Detailed Tool Analysis")
    lines.append("")

    for tool in tools:
        if tool not in results:
            continue

        tool_results = results[tool]
        lines.append(f"### {tool.upper()}")
        lines.append("")

        # Stats
        lines.append("**Performance Metrics:**")
        lines.append(f"- Total Findings: {tool_results.get('total_findings', 0)}")
        lines.append(f"- True Positives: {tool_results.get('true_positives', 0)}")
        lines.append(f"- False Positives: {tool_results.get('false_positives', 0)}")
        lines.append(f"- False Negatives: {tool_results.get('false_negatives', 0)}")
        lines.append("")

        # Detected vulnerabilities
        detected = tool_results.get('detected_vulnerabilities', [])
        lines.append(f"**Detected Vulnerabilities ({len(detected)}):**")
        if detected:
            for vuln in detected:
                lines.append(f"- {vuln}")
        else:
            lines.append("- None")
        lines.append("")

        # Missed vulnerabilities
        missed = tool_results.get('missed_vulnerabilities', [])
        lines.append(f"**Missed Vulnerabilities ({len(missed)}):**")
        if missed:
            for vuln in missed:
                lines.append(f"- {vuln}")
        else:
            lines.append("- None")
        lines.append("")

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    lines.append("Based on the benchmark results:")
    lines.append("")
    lines.append("1. **For Maximum Coverage:** Use CodeQL for its superior recall and semantic analysis capabilities.")
    lines.append("2. **For CI/CD Integration:** Use Semgrep for its speed and low false positive rate.")
    lines.append("3. **For Deep Taint Analysis:** Use Pysa for complex inter-procedural flows.")
    lines.append("4. **Best Practice:** Combine multiple tools for defense in depth.")
    lines.append("")

    # Methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append("### Ground Truth")
    lines.append("The benchmark uses a set of 16 intentionally vulnerable code patterns in VulnShop,")
    lines.append("each documented with expected taint flows and detection status per tool.")
    lines.append("")
    lines.append("### Metrics")
    lines.append("- **Precision:** True Positives / (True Positives + False Positives)")
    lines.append("- **Recall:** True Positives / (True Positives + False Negatives)")
    lines.append("- **F1 Score:** Harmonic mean of Precision and Recall")
    lines.append("")
    lines.append("### Limitations")
    lines.append("- Detection matching uses heuristics (file/line matching)")
    lines.append("- Some vulnerabilities are inherently harder to detect statically")
    lines.append("- Tool configurations may not be fully optimized")
    lines.append("")

    # Footer
    lines.append("---")
    lines.append("")
    lines.append("*Generated by VulnShop Benchmark Suite*")

    # Write file
    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        f.write('\n'.join(lines))

    return output_file


def generate_csv_export(data: Dict[str, Any], output_dir: Path) -> List[Path]:
    """Generate CSV exports of benchmark data."""

    output_files = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # Summary CSV
    summary_file = output_dir / "benchmark_summary.csv"
    with open(summary_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Tool', 'Total Findings', 'True Positives', 'False Positives',
                         'False Negatives', 'Precision', 'Recall', 'F1 Score', 'Execution Time'])

        for tool, results in data.get('results', {}).items():
            writer.writerow([
                tool,
                results.get('total_findings', 0),
                results.get('true_positives', 0),
                results.get('false_positives', 0),
                results.get('false_negatives', 0),
                results.get('precision', 0),
                results.get('recall', 0),
                results.get('f1_score', 0),
                results.get('execution_time', 0)
            ])
    output_files.append(summary_file)

    # Detection matrix CSV
    matrix_file = output_dir / "detection_matrix.csv"
    tools = data.get('tools_analyzed', [])
    with open(matrix_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Vulnerability'] + [t.upper() for t in tools])

        for vuln_id, detections in sorted(data.get('comparison_matrix', {}).items()):
            row = [vuln_id]
            for tool in tools:
                row.append('Yes' if detections.get(tool, False) else 'No')
            writer.writerow(row)
    output_files.append(matrix_file)

    return output_files


def generate_html_report(data: Dict[str, Any], output_dir: Path, include_charts: bool = False) -> Path:
    """Generate an HTML report with optional charts."""

    output_file = output_dir / "benchmark_report.html"

    tools = data.get('tools_analyzed', [])
    results = data.get('results', {})
    comparison = data.get('comparison_matrix', {})

    html = []
    html.append('<!DOCTYPE html>')
    html.append('<html lang="en">')
    html.append('<head>')
    html.append('  <meta charset="UTF-8">')
    html.append('  <meta name="viewport" content="width=device-width, initial-scale=1.0">')
    html.append('  <title>VulnShop Benchmark Report</title>')
    html.append('  <style>')
    html.append('''
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; line-height: 1.6; }
    h1 { color: #1a1a2e; border-bottom: 3px solid #4361ee; padding-bottom: 10px; }
    h2 { color: #16213e; margin-top: 40px; }
    h3 { color: #0f3460; }
    table { border-collapse: collapse; width: 100%; margin: 20px 0; }
    th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
    th { background-color: #4361ee; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    tr:hover { background-color: #e8e8e8; }
    .metric-card { display: inline-block; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 30px; margin: 10px; border-radius: 10px; text-align: center; }
    .metric-value { font-size: 2em; font-weight: bold; }
    .metric-label { font-size: 0.9em; opacity: 0.9; }
    .detected { color: #10b981; font-weight: bold; }
    .missed { color: #ef4444; font-weight: bold; }
    .summary-box { background: #f8f9fa; border-left: 4px solid #4361ee; padding: 20px; margin: 20px 0; }
    .chart-container { margin: 30px 0; text-align: center; }
    ''')
    html.append('  </style>')
    html.append('</head>')
    html.append('<body>')

    # Header
    html.append('<h1>VulnShop Taint Analysis Benchmark Report</h1>')
    html.append(f'<p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>')
    html.append(f'<p><strong>Benchmark Run:</strong> {data.get("timestamp", "Unknown")}</p>')

    # Metric Cards
    html.append('<div style="margin: 30px 0;">')
    for tool in tools:
        if tool in results:
            f1 = results[tool].get('f1_score', 0)
            html.append(f'''
            <div class="metric-card">
                <div class="metric-value">{f1:.1%}</div>
                <div class="metric-label">{tool.upper()} F1 Score</div>
            </div>
            ''')
    html.append('</div>')

    # Summary Table
    html.append('<h2>Performance Summary</h2>')
    html.append('<table>')
    html.append('<tr><th>Metric</th>' + ''.join(f'<th>{t.upper()}</th>' for t in tools) + '</tr>')

    metrics = [
        ('Total Findings', 'total_findings', lambda x: str(x)),
        ('True Positives', 'true_positives', lambda x: str(x)),
        ('Precision', 'precision', lambda x: f'{x:.1%}'),
        ('Recall', 'recall', lambda x: f'{x:.1%}'),
        ('F1 Score', 'f1_score', lambda x: f'{x:.1%}'),
        ('Execution Time', 'execution_time', lambda x: f'{x:.1f}s'),
    ]

    for label, key, formatter in metrics:
        row = f'<tr><td><strong>{label}</strong></td>'
        for tool in tools:
            if tool in results:
                value = results[tool].get(key, 0)
                row += f'<td>{formatter(value)}</td>'
            else:
                row += '<td>-</td>'
        row += '</tr>'
        html.append(row)

    html.append('</table>')

    # Detection Matrix
    html.append('<h2>Detection Matrix</h2>')
    html.append('<table>')
    html.append('<tr><th>Vulnerability</th>' + ''.join(f'<th>{t.upper()}</th>' for t in tools) + '</tr>')

    for vuln_id, detections in sorted(comparison.items()):
        row = f'<tr><td>{vuln_id}</td>'
        for tool in tools:
            detected = detections.get(tool, False)
            icon = '<span class="detected">✓</span>' if detected else '<span class="missed">✗</span>'
            row += f'<td style="text-align: center;">{icon}</td>'
        row += '</tr>'
        html.append(row)

    html.append('</table>')

    # Charts (if matplotlib available and requested)
    if include_charts:
        try:
            chart_path = generate_charts(data, output_dir)
            if chart_path:
                html.append('<h2>Performance Charts</h2>')
                html.append(f'<div class="chart-container"><img src="charts/comparison_chart.png" alt="Performance Comparison" style="max-width: 100%;"></div>')
        except ImportError:
            html.append('<p><em>Charts not generated (matplotlib not available)</em></p>')

    # Footer
    html.append('<hr>')
    html.append('<p><em>Generated by VulnShop Benchmark Suite</em></p>')
    html.append('</body></html>')

    output_dir.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w') as f:
        f.write('\n'.join(html))

    return output_file


def generate_charts(data: Dict[str, Any], output_dir: Path) -> Optional[Path]:
    """Generate comparison charts using matplotlib."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib
        matplotlib.use('Agg')  # Non-interactive backend
    except ImportError:
        return None

    charts_dir = output_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    tools = data.get('tools_analyzed', [])
    results = data.get('results', {})

    # Metrics comparison bar chart
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    metrics = ['precision', 'recall', 'f1_score']
    titles = ['Precision', 'Recall', 'F1 Score']
    colors = ['#4361ee', '#3a0ca3', '#7209b7']

    for ax, metric, title, color in zip(axes, metrics, titles, colors):
        values = [results.get(tool, {}).get(metric, 0) for tool in tools]
        bars = ax.bar([t.upper() for t in tools], values, color=color, alpha=0.8)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_ylim(0, 1)
        ax.set_ylabel('Score')

        # Add value labels on bars
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                    f'{val:.1%}', ha='center', va='bottom', fontsize=10)

    plt.tight_layout()
    chart_path = charts_dir / "comparison_chart.png"
    plt.savefig(chart_path, dpi=150, bbox_inches='tight')
    plt.close()

    return chart_path


def main():
    parser = argparse.ArgumentParser(description="Generate benchmark reports")
    parser.add_argument('--input', type=str, default=str(DEFAULT_INPUT),
                        help='Input benchmark results JSON')
    parser.add_argument('--output', type=str, default=str(DEFAULT_OUTPUT),
                        help='Output directory')
    parser.add_argument('--format', type=str, default='all',
                        choices=['markdown', 'html', 'csv', 'all'],
                        help='Output format')
    parser.add_argument('--include-charts', action='store_true',
                        help='Generate chart images')

    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.output)

    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}")
        print("Run benchmarks first: python run_benchmarks.py")
        return 1

    print(f"Loading results from: {input_path}")
    data = load_results(input_path)

    formats = ['markdown', 'html', 'csv'] if args.format == 'all' else [args.format]

    for fmt in formats:
        if fmt == 'markdown':
            output = generate_markdown_report(data, output_dir)
            print(f"Generated Markdown report: {output}")
        elif fmt == 'html':
            output = generate_html_report(data, output_dir, args.include_charts)
            print(f"Generated HTML report: {output}")
        elif fmt == 'csv':
            outputs = generate_csv_export(data, output_dir)
            for output in outputs:
                print(f"Generated CSV export: {output}")

    return 0


if __name__ == '__main__':
    exit(main())
