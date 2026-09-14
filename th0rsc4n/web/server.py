"""
TH0RSC4N Web UI — Flask Server (Async)
Non-blocking scan execution via asyncio.run() bridge.
"""
import asyncio
import json
import time
from pathlib import Path
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file

from th0rsc4n.core.scanner import Scanner
from th0rsc4n.modules import get_modules, get_mode_info, SCAN_MODES
from th0rsc4n.utils.helpers import normalize_url, is_valid_url


# ==========================================
# CONFIG
# ==========================================
REPORT_DIR = Path("th0rsc4n-reports")
REPORT_DIR.mkdir(exist_ok=True)


# ==========================================
# ASYNC EXECUTOR
# ==========================================
async def _run_module(engine, name, func, errors):
    """Execute single module (adaptive async/sync)."""
    try:
        if asyncio.iscoroutinefunction(func):
            await func(engine)
        else:
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, func, engine)
    except Exception as e:
        errors.append(f"{name}: {e}")


async def _run_async_web_scan(scanner_instance, modules):
    """Run all modules with persistent session + bounded concurrency."""
    errors = []

    async with scanner_instance as engine:
        # Bounded concurrency biar gak flood target
        sem = asyncio.Semaphore(4)

        async def _wrapped(name, func):
            async with sem:
                await _run_module(engine, name, func, errors)

        tasks = [_wrapped(name, func) for name, func in modules]
        await asyncio.gather(*tasks, return_exceptions=True)

    return errors


# ==========================================
# APP FACTORY
# ==========================================
def create_app():
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # ==========================================
    # INDEX
    # ==========================================
    @app.route("/")
    def index():
        return render_template("index.html")

    # ==========================================
    # API: SCAN (ASYNC)
    # ==========================================
    @app.route("/api/scan", methods=["POST"])
    def api_scan():
        try:
            data = request.get_json() or {}
        except Exception:
            return jsonify({"error": "Invalid JSON body"}), 400

        target = (data.get("target") or "").strip()
        mode = (data.get("mode") or "normal").lower()

        if not target:
            return jsonify({"error": "Target URL wajib diisi"}), 400

        # Normalize & validate
        if not is_valid_url(target):
            target = "https://" + target
        if not is_valid_url(target):
            return jsonify({"error": "Format URL tidak valid"}), 400

        target = normalize_url(target)

        # Ambil modules sesuai mode
        modules = get_modules(mode)
        mode_info = get_mode_info(mode)

        # Init scanner
        scanner = Scanner(target, timeout=10, verbose=False)

        start = time.time()

        try:
            # Bridge Flask (sync) → asyncio
            errors = asyncio.run(_run_async_web_scan(scanner, modules))
        except RuntimeError:
            # Kalau sudah ada event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                errors = loop.run_until_complete(
                    _run_async_web_scan(scanner, modules)
                )
            finally:
                loop.close()
        except Exception as e:
            return jsonify({"error": f"Scan engine error: {str(e)}"}), 500

        elapsed = time.time() - start
        stats = scanner.summary()

        # Group findings by category
        grouped = {}
        for f in scanner.findings:
            grouped.setdefault(f.category, []).append(f.to_dict())

        # Detected tech
        detected_tech = getattr(scanner, "detected_tech", [])
        tech_by_category = getattr(scanner, "tech_by_category", {})

        # Save report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_id = f"scan_{timestamp}"

        json_path = REPORT_DIR / f"{report_id}.json"
        report_payload = {
            "tool": "TH0RSC4N",
            "version": "1.0.0",
            "target": target,
            "mode": mode,
            "scan_date": datetime.now().isoformat(),
            "elapsed": round(elapsed, 2),
            "summary": stats,
            "total_findings": len(scanner.findings),
            "findings": [f.to_dict() for f in scanner.findings],
            "technologies": detected_tech,
            "tech_by_category": tech_by_category,
            "module_errors": errors,
        }

        try:
            with open(json_path, "w", encoding="utf-8") as fp:
                json.dump(report_payload, fp, indent=2, ensure_ascii=False)
        except Exception as e:
            return jsonify({"error": f"Gagal simpan report: {str(e)}"}), 500

        return jsonify({
            "success": True,
            "report_id": report_id,
            "target": target,
            "mode": mode,
            "mode_name": mode_info["name"],
            "elapsed": round(elapsed, 2),
            "summary": stats,
            "grouped": grouped,
            "technologies": detected_tech,
            "tech_by_category": tech_by_category,
            "total_findings": len(scanner.findings),
            "module_errors": errors[:5] if errors else [],
        })

    # ==========================================
    # API: DOWNLOAD
    # ==========================================
    @app.route("/api/download/<report_id>/<fmt>")
    def download(report_id, fmt):
        # Sanitize input
        report_id = Path(report_id).name
        fmt = fmt.lower()

        json_path = REPORT_DIR / f"{report_id}.json"
        if not json_path.exists():
            return jsonify({"error": "Report tidak ditemukan"}), 404

        # ---------- JSON ----------
        if fmt == "json":
            return send_file(
                json_path,
                as_attachment=True,
                download_name=f"{report_id}.json",
                mimetype="application/json",
            )

        # ---------- HTML ----------
        if fmt == "html":
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                from th0rsc4n.core.finding import Finding
                from th0rsc4n.reporters import html as html_rep

                findings = [Finding(**f) for f in data.get("findings", [])]

                html_path = REPORT_DIR / f"{report_id}.html"
                html_rep.report(findings, data.get("target", ""), html_path)

                return send_file(
                    html_path,
                    as_attachment=True,
                    download_name=f"{report_id}.html",
                    mimetype="text/html",
                )
            except Exception as e:
                return jsonify({"error": f"Gagal generate HTML: {str(e)}"}), 500

        # ---------- MARKDOWN ----------
        if fmt in ("md", "markdown"):
            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                from th0rsc4n.core.finding import Finding
                from th0rsc4n.reporters import markdown

                findings = [Finding(**f) for f in data.get("findings", [])]

                md_path = REPORT_DIR / f"{report_id}.md"
                markdown.report(findings, data.get("target", ""), md_path)

                return send_file(
                    md_path,
                    as_attachment=True,
                    download_name=f"{report_id}.md",
                    mimetype="text/markdown",
                )
            except Exception as e:
                return jsonify({"error": f"Gagal generate Markdown: {str(e)}"}), 500

        return jsonify({"error": "Format tidak didukung"}), 400

    # ==========================================
    # API: MODES
    # ==========================================
    @app.route("/api/modes")
    def api_modes():
        return jsonify({
            key: {
                "name": info["name"],
                "icon": info["icon"],
                "description": info["description"],
                "eta": info["eta"],
                "modules": len(info["modules"]),
            }
            for key, info in SCAN_MODES.items()
        })

    # ==========================================
    # API: HEALTH
    # ==========================================
    @app.route("/api/health")
    def api_health():
        return jsonify({
            "status": "ok",
            "tool": "TH0RSC4N",
            "version": "1.0.0",
            "reports_dir": str(REPORT_DIR),
            "total_reports": len(list(REPORT_DIR.glob("*.json"))),
        })

    # ==========================================
    # ERROR HANDLERS
    # ==========================================
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint tidak ditemukan"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app


# ==========================================
# START SERVER
# ==========================================
def start_server(host="127.0.0.1", port=5000, open_browser=False):
    """Start Flask web server."""
    app = create_app()

    if open_browser:
        try:
            import webbrowser
            import threading
            url = f"http://{host}:{port}"

            def _open():
                import time as _t
                _t.sleep(1.2)
                webbrowser.open(url)

            threading.Thread(target=_open, daemon=True).start()
        except Exception:
            pass

    print(f"""
╭──────────────────────────────────────────╮
│  TH0RSC4N Web UI                         │
│                                          │
│  Buka di browser:                        │
│  http://{host}:{port}                    │
│                                          │
│  Tekan Ctrl+C untuk stop                 │
╰──────────────────────────────────────────╯
""")

    try:
        app.run(host=host, port=port, debug=False, threaded=True)
    except KeyboardInterrupt:
        print("\n[!] Server dihentikan")


# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":
    start_server()