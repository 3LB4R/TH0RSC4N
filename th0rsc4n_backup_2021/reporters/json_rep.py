"""JSON Reporter — OWASP 2025 grouped."""
import json
from datetime import datetime
from collections import defaultdict


def report(findings, target, output_path):
    """Generate JSON report grouped by OWASP 2025."""
    stats = {}
    owasp_groups = defaultdict(list)

    for f in findings:
        # Stats
        stats[f.severity] = stats.get(f.severity, 0) + 1

        # Group by OWASP 2025
        code = getattr(f, "owasp_2025_code", "A10:2025")
        cat = getattr(f, "owasp_2025_category", "Unknown")
        owasp_groups[f"{code} - {cat}"].append(f.to_dict())

    data = {
        "tool": "TH0RSC4N",
        "version": "1.0.0",
        "owasp_version": "2025",
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "summary": {
            "total": len(findings),
            "by_severity": stats,
            "by_owasp_2025": {
                k: len(v) for k, v in owasp_groups.items()
            },
        },
        "findings_by_owasp_2025": dict(owasp_groups),
        "raw_findings": [f.to_dict() for f in findings],
    }

    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)

    return output_path
