"""TH0RSC4N Web UI - Flask Server"""
import json
import time
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file

from th0rsc4n.core.scanner import Scanner
from th0rsc4n.modules import get_modules, get_mode_info
from th0rsc4n.utils.helpers import normalize_url, is_valid_url


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    
    @app.route("/")
    def index():
        return render_template("index.html")
    
    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        data = request.get_json()
        target = data.get("target", "").strip()
        mode = data.get("mode", "normal")
        
        if not target:
            return jsonify({"error": "Target required"}), 400
        
        target = normalize_url(target)
        if not is_valid_url(target):
            return jsonify({"error": "Invalid URL"}), 400
        
        # Jalankan scan
        start = time.time()
        scanner = Scanner(target)
        modules = get_modules(mode)
        
        for name, func in modules:
            try:
                func(scanner)
            except Exception as e:
                pass
        
        elapsed = time.time() - start
        stats = scanner.summary()
        
        # Group findings
        grouped = {}
        for f in scanner.findings:
            grouped.setdefault(f.category, []).append(f.to_dict())
        
        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path("th0rsc4n-reports")
        report_dir.mkdir(exist_ok=True)
        
        json_path = report_dir / f"scan_{timestamp}.json"
        with open(json_path, "w") as fp:
            json.dump({
                "target": target,
                "mode": mode,
                "scan_date": datetime.now().isoformat(),
                "elapsed": elapsed,
                "summary": stats,
                "findings": [f.to_dict() for f in scanner.findings],
            }, fp, indent=2)
        
        return jsonify({
            "target": target,
            "mode": mode,
            "elapsed": elapsed,
            "summary": stats,
            "grouped": grouped,
            "report_id": timestamp,
        })
    
    @app.route("/api/download/<report_id>/<format>")
    def download(report_id, format):
        report_dir = Path("th0rsc4n-reports")
        json_path = report_dir / f"scan_{report_id}.json"
        
        if not json_path.exists():
            return "Report not found", 404
        
        with open(json_path) as f:
            data = json.load(f)
        
        if format == "json":
            return send_file(json_path, as_attachment=True)
        
        elif format == "html":
            from th0rsc4n.reporters import html as html_rep
            from th0rsc4n.core.finding import Finding
            
            findings = [Finding(**f) for f in data["findings"]]
            html_path = report_dir / f"scan_{report_id}.html"
            html_rep.report(findings, data["target"], html_path)
            return send_file(html_path, as_attachment=True)
        
        elif format == "md":
            from th0rsc4n.reporters import markdown
            from th0rsc4n.core.finding import Finding
            
            findings = [Finding(**f) for f in data["findings"]]
            md_path = report_dir / f"scan_{report_id}.md"
            markdown.report(findings, data["target"], md_path)
            return send_file(md_path, as_attachment=True)
        
        return "Invalid format", 400
    
    @app.route("/api/modes")
    def api_modes():
        from th0rsc4n.modules import SCAN_MODES
        return jsonify({
            k: {
                "name": v["name"],
                "icon": v["icon"],
                "description": v["description"],
                "eta": v["eta"],
                "modules": len(v["modules"]),
            }
            for k, v in SCAN_MODES.items()
        })
    
    return app


def start_server(target=None, mode="normal", output=None, host="127.0.0.1", port=5000):
    """Start web server."""
    app = create_app()
    
    print(f"""
╭──────────────────────────────────────────╮
│  🌐 TH0RSC4N Web UI                      │
│                                          │
│  Buka di browser:                        │
│  http://{host}:{port}                       │
│                                          │
│  Tekan Ctrl+C untuk stop                 │
╰──────────────────────────────────────────╯
""")
    
    app.run(host=host, port=port, debug=False)