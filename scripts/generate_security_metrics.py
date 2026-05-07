import argparse
import glob
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def load_sarif(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_rule_index(run: dict) -> dict:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    return {rule.get("id"): rule for rule in rules if rule.get("id")}


def normalize_severity(level: str) -> str:
    normalized = str(level).upper()
    if normalized == "ERROR":
        return "CRITICAL"
    if normalized == "WARNING":
        return "HIGH"
    if normalized in SEVERITY_ORDER:
        return normalized
    return "UNKNOWN"


def extract_severity(result: dict, rule: dict) -> str:
    message = result.get("message", {}).get("text", "")
    severity_match = re.search(r"Severity:\s*(UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL)", message, re.IGNORECASE)
    if severity_match:
        return severity_match.group(1).upper()

    properties = result.get("properties", {})
    for key in ("severity", "Severity"):
        value = properties.get(key)
        if isinstance(value, str) and value:
            return normalize_severity(value)

    rule_properties = rule.get("properties", {})
    for key in ("security-severity", "severity", "Severity"):
        value = rule_properties.get(key)
        if isinstance(value, str) and value:
            return normalize_severity(value)

    return normalize_severity(result.get("level", "unknown"))


def sanitize_label(value: str) -> str:
    sanitized = []
    for char in value.lower():
        if char.isalnum():
            sanitized.append(char)
        else:
            sanitized.append("_")
    compacted = re.sub(r"_+", "_", "".join(sanitized)).strip("_")
    return compacted or "unknown"


def collect_metrics(sarif_files: list[Path]) -> tuple[Counter, Counter, dict[str, Counter]]:
    severity_counts: Counter = Counter()
    report_counts: Counter = Counter()
    report_severity_counts: dict[str, Counter] = defaultdict(Counter)

    for sarif_file in sarif_files:
        data = load_sarif(sarif_file)
        report_name = sanitize_label(sarif_file.stem.removeprefix("trivy-"))

        for run in data.get("runs", []):
            rule_index = build_rule_index(run)
            for result in run.get("results", []):
                rule = rule_index.get(result.get("ruleId", "Unknown"), {})
                severity = extract_severity(result, rule)
                severity_counts[severity] += 1
                report_counts[report_name] += 1
                report_severity_counts[report_name][severity] += 1

    return severity_counts, report_counts, report_severity_counts


def render_metrics(sarif_files: list[Path]) -> str:
    severity_counts, report_counts, report_severity_counts = collect_metrics(sarif_files)

    lines = [
        "# HELP security_findings_total Nombre total de vulnerabilites par severite.",
        "# TYPE security_findings_total gauge",
    ]

    for severity in SEVERITY_ORDER:
        lines.append(f'security_findings_total{{severity="{severity.lower()}"}} {severity_counts.get(severity, 0)}')

    lines.extend(
        [
            "# HELP security_findings_by_report_total Nombre total de vulnerabilites par rapport SARIF.",
            "# TYPE security_findings_by_report_total gauge",
        ]
    )

    for report_name in sorted(report_counts):
        lines.append(f'security_findings_by_report_total{{report="{report_name}"}} {report_counts[report_name]}')

    lines.extend(
        [
            "# HELP security_findings_by_report_severity_total Nombre total de vulnerabilites par rapport et severite.",
            "# TYPE security_findings_by_report_severity_total gauge",
        ]
    )

    for report_name in sorted(report_severity_counts):
        for severity in SEVERITY_ORDER:
            lines.append(
                f'security_findings_by_report_severity_total{{report="{report_name}",severity="{severity.lower()}"}} '
                f'{report_severity_counts[report_name].get(severity, 0)}'
            )

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Prometheus metrics from Trivy SARIF files.")
    parser.add_argument(
        "--input-glob",
        default="trivy-*.sarif",
        help="Glob pattern used to find SARIF files.",
    )
    parser.add_argument(
        "--output",
        default="monitoring/textfile_collector/security_findings.prom",
        help="Output Prometheus metrics file path.",
    )
    args = parser.parse_args()

    sarif_files = sorted(Path(path) for path in glob.glob(args.input_glob))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_metrics(sarif_files), encoding="utf-8")


if __name__ == "__main__":
    main()
