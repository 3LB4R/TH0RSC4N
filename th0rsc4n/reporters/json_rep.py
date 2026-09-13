import json
from datetime import datetime

def report(findings, target, output_path):
    stats = {}
    for f in findings:
        stats[f.severity] = stats.get(f.severity, 0) + 1
    
    data = {
        "tool": "TH0RSC4N",
        "version": "1.0.0",
        "author": "Thorranov",
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "summary": stats,
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)
    
    return output_path