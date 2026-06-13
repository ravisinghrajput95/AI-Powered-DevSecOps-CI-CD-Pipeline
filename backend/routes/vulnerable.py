"""Intentionally vulnerable utility endpoints for DevSecOps training"""

import os
import requests
from flask import Blueprint, request, jsonify, send_file
from config import UPLOAD_FOLDER, INTERNAL_SERVICES

vuln_bp = Blueprint("vulnerable", __name__)


@vuln_bp.route("/fetch", methods=["POST"])
def ssrf_fetch():
    """VULN: SSRF - fetches arbitrary URLs including internal services"""
    data = request.get_json() or {}
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "url required"}), 400

    try:
        resp = requests.get(url, timeout=10, verify=False)
        return jsonify(
            {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:10000],
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@vuln_bp.route("/proxy", methods=["GET"])
def ssrf_proxy():
    """VULN: SSRF via GET parameter"""
    url = request.args.get("url", INTERNAL_SERVICES["metadata"])
    resp = requests.get(url, timeout=5, verify=False)
    return (
        resp.text,
        resp.status_code,
        {"Content-Type": resp.headers.get("Content-Type", "text/plain")},
    )


@vuln_bp.route("/file", methods=["GET"])
def path_traversal():
    """VULN: Path traversal - reads arbitrary files"""
    filepath = request.args.get("path", "/etc/passwd")
    # No sanitization of path
    full_path = os.path.join("/", filepath.lstrip("/"))
    try:
        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
            return jsonify({"content": f.read()[:50000]})
    except Exception as e:
        return jsonify({"error": str(e), "attempted_path": full_path}), 500


@vuln_bp.route("/upload", methods=["POST"])
def insecure_upload():
    """VULN: Insecure file upload - no type validation, executable allowed"""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    filename = file.filename  # VULN: uses original filename including path traversal
    save_path = os.path.join(UPLOAD_FOLDER, filename)
    os.makedirs(
        os.path.dirname(save_path) if os.path.dirname(save_path) else UPLOAD_FOLDER,
        exist_ok=True,
    )
    file.save(save_path)

    return jsonify(
        {
            "message": "File uploaded",
            "filename": filename,
            "path": save_path,
            "url": f"/api/vuln/download?filename={filename}",
        }
    )


@vuln_bp.route("/download", methods=["GET"])
def download_upload():
    filename = request.args.get("filename", "")
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    return send_file(filepath)


@vuln_bp.route("/debug", methods=["GET"])
def debug_info():
    """VULN: Debug endpoint exposes stack and config in production"""
    from flask import current_app
    import config as cfg

    return jsonify(
        {
            "debug": cfg.DEBUG,
            "config": {k: v for k, v in vars(cfg).items() if not k.startswith("_")},
            "routes": [str(rule) for rule in current_app.url_map.iter_rules()],
        }
    )
