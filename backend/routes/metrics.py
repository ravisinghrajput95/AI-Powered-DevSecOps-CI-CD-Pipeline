"""Prometheus metrics endpoint"""

from flask import Blueprint, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest

metrics_bp = Blueprint("metrics", __name__)

REQUEST_COUNT = Counter(
    "cloudcart_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)
REQUEST_LATENCY = Histogram(
    "cloudcart_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)


@metrics_bp.route("/metrics")
def prometheus_metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
