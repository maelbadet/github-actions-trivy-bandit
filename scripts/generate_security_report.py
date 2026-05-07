import argparse
import glob
import json
from collections import Counter
from pathlib import Path


def load_sarif(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def build_rule_index(run: dict) -> dict:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    return {rule.get("id"): rule for rule in rules if rule.get("id")}


def extract_cwe(rule: dict) -> str:
    properties = rule.get("properties", {})
    tags = properties.get("tags", [])
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("CWE-"):
            return tag

    relationships = rule.get("relationships", [])
    for relation in relationships:
        target = relation.get("target", {})
        rule_id = target.get("id")
        if isinstance(rule_id, str) and rule_id.startswith("CWE-"):
            return rule_id

    return "N/A"


def extract_target(result: dict, source_name: str) -> str:
    locations = result.get("locations", [])
    if locations:
        artifact = locations[0].get("physicalLocation", {}).get("artifactLocation", {})
        uri = artifact.get("uri")
        if uri:
            return uri
    return source_name


def normalize_severity(level: str) -> str:
    normalized = str(level).upper()
    if normalized == "ERROR":
        return "CRITICAL"
    if normalized == "WARNING":
        return "HIGH"
    return normalized


def extract_findings(sarif_path: Path) -> list[dict]:
    data = load_sarif(sarif_path)
    findings = []

    for run in data.get("runs", []):
        rule_index = build_rule_index(run)
        tool_name = run.get("tool", {}).get("driver", {}).get("name", "Trivy")

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "Unknown")
            rule = rule_index.get(rule_id, {})
            level = normalize_severity(result.get("level", "unknown"))
            message = result.get("message", {}).get("text", "No description provided.")
            cwe = extract_cwe(rule)
            help_uri = rule.get("helpUri", "N/A")
            short_description = rule.get("shortDescription", {}).get("text", rule_id)

            findings.append(
                {
                    "tool": tool_name,
                    "source": sarif_path.name,
                    "rule_id": rule_id,
                    "title": short_description,
                    "level": level,
                    "message": message,
                    "cwe": cwe,
                    "target": extract_target(result, sarif_path.stem),
                    "help_uri": help_uri,
                }
            )

    return findings


def render_markdown(findings: list[dict]) -> str:
    severity_counts = Counter(finding["level"] for finding in findings)
    source_counts = Counter(finding["source"] for finding in findings)

    lines = [
        "# Security and Quality Findings",
        "",
        "## Summary",
        f"- Total findings: {len(findings)}",
        f"- CRITICAL: {severity_counts.get('CRITICAL', 0)}",
        f"- HIGH: {severity_counts.get('HIGH', 0)}",
        "",
        "## Findings by Report",
    ]

    for source_name, count in sorted(source_counts.items()):
        lines.append(f"- {source_name}: {count}")

    if not findings:
        lines.extend(
            [
                "",
                "## Findings",
                "No HIGH or CRITICAL findings were detected in the scanned SARIF reports.",
            ]
        )
        return "\n".join(lines) + "\n"

    lines.extend(["", "## Findings"])

    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding['title']}",
                f"- Rule ID: {finding['rule_id']}",
                f"- Severity: {finding['level']}",
                f"- CWE: {finding['cwe']}",
                f"- Target: {finding['target']}",
                f"- Source report: {finding['source']}",
                f"- Description: {finding['message']}",
                f"- Reference: {finding['help_uri']}",
                "",
            ]
        )

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Markdown report from Trivy SARIF files.")
    parser.add_argument(
        "--input-glob",
        default="trivy-*.sarif",
        help="Glob pattern used to find SARIF files.",
    )
    parser.add_argument(
        "--output",
        default="SECURITY_AND_QUALITY_FINDINGS.md",
        help="Output Markdown report path.",
    )
    args = parser.parse_args()

    sarif_files = sorted(Path(path) for path in glob.glob(args.input_glob))
    findings = []
    for sarif_file in sarif_files:
        findings.extend(extract_findings(sarif_file))

    output = Path(args.output)
    output.write_text(render_markdown(findings), encoding="utf-8")


if __name__ == "__main__":
    main()
