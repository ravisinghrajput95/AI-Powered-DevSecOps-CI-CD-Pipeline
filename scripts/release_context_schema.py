#!/usr/bin/env python3
"""
The canonical final_release_context.json schema, as an importable Python
module — same rationale as executive_report_schema.py: no separately-
committed file at a path that has to be gotten exactly right, single
source of truth for both producers (compose_release_context.py) and
consumers (the test suite, renderers).

This schema didn't exist before this module — ExecutiveReport had one,
ReleaseContext never did, despite being the platform's actual canonical
evidence contract. That asymmetry is exactly the kind of thing the
earlier "enterprise-grade platform" review flagged and it never got
built. Writing it now, retroactively, against the REAL verified shape
confirmed across many real pipeline runs this session — not a fresh
design, a description of what already exists and is already trusted.

Deliberately less strict than executive_report_schema.py in a few
specific places, and that's a judgment call worth stating explicitly:
`sbom_summary`, `dependency_summary`, `remediation_guide`, and
`supply_chain`'s sub-shapes were never rigidly specified during this
project's development the way ExecutiveReport's fields were — retroactively
forcing a strict shape onto them now would be inventing a constraint
that was never actually a real contract, not closing a real gap. Strict
where it matters most (the Finding object, domain/severity/scan_status
enums, the provenance structure) — loose where the real history shows it
was never tightly specified.
"""

SEVERITY_VALUES = ["critical", "high", "medium", "low", "informational"]
DOMAIN_VALUES = ["application_security", "infrastructure_security", "runtime_security", "container_security"]
TYPE_VALUES = ["security", "quality"]
SCAN_STATUS_VALUES = ["SUCCESS", "FAILED", "SKIPPED", "NOT_CONFIGURED"]
VERIFICATION_STATUS_VALUES = ["SUCCESS", "FAILED", "UNKNOWN", "SKIPPED"]

FINDING_SCHEMA = {
    "type": "object",
    "required": ["finding_id", "component", "tool", "rule_id", "severity", "category", "type", "confidence", "occurrence_count", "domain", "sample_message"],
    "additionalProperties": True,  # Snyk-specific fields (package_*), locations, etc. legitimately vary by tool
    "properties": {
        "finding_id": {"type": "string", "pattern": "^[a-f0-9]{12}$"},
        "component": {"type": "string"},
        "tool": {"type": "string"},
        "rule_id": {"type": ["string", "null"]},
        "severity": {"type": "string", "enum": SEVERITY_VALUES},
        "category": {"type": "string"},
        "type": {"type": "string", "enum": TYPE_VALUES},
        "confidence": {"type": "string"},
        "occurrence_count": {"type": "integer", "minimum": 1},
        "domain": {"type": "string", "enum": DOMAIN_VALUES},
        "sample_message": {"type": ["string", "null"]},
        "original_severity": {"type": "string"},
        "original_severities": {"type": "array", "items": {"type": "string"}},
        "remediation_notes": {"type": "array", "items": {"type": "string"}},
        "package_name": {"type": "string"},
        "package_version": {"type": "string"},
        "package_manager": {"type": "string"},
        "locations": {"type": "array", "items": {"type": "string"}},
        "total_locations": {"type": "integer", "minimum": 0},
        "locations_truncated": {"type": "boolean"},
        "delta_status": {"type": "string"},
    },
}

PROVENANCE_SOURCE_SCHEMA = {
    "type": "object",
    "additionalProperties": True,
    "required": ["source_version", "source_generated_at"],
    "properties": {
        "source_version": {"type": ["string", "null"]},
        "source_generated_at": {"type": ["string", "null"]},
    },
}

SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ReleaseContext",
    "description": "The canonical, deterministic evidence contract produced by compose_release_context.py. Contains deterministic facts ONLY — no AI reasoning, no opinions. Consumed by the AI Release Intelligence Engine and any future Renderer/Backstage/dashboard.",
    "type": "object",
    "additionalProperties": True,  # forward-compatible: a future field shouldn't break consumers, see Open-World Enum Policy in system_prompt.md
    "required": ["schema_version", "release", "provenance", "findings", "remediation_guide", "scan_status", "release_statistics", "signal_availability"],
    "properties": {
        "schema_version": {"type": "string"},
        "release": {
            "type": "object",
            "required": ["version", "repository", "components", "generated_at"],
            "additionalProperties": True,
            "properties": {
                "version": {"type": "string"},
                "repository": {"type": "string"},
                "components": {"type": "array", "items": {"type": "string"}},
                "generated_at": {"type": "string"},
            },
        },
        "provenance": {
            "type": "object",
            "additionalProperties": True,
            "properties": {
                "application_security": {"type": "object", "additionalProperties": True},
                "infrastructure_security": {"type": "object", "additionalProperties": True},
                "runtime_security": {"type": "object", "additionalProperties": True},
            },
        },
        "findings": {"type": "array", "items": FINDING_SCHEMA},
        "remediation_guide": {"type": "object", "additionalProperties": True},
        "scan_status": {
            "type": "object",
            "additionalProperties": {
                "type": "object",
                "additionalProperties": {"type": "string", "enum": SCAN_STATUS_VALUES},
            },
        },
        "release_statistics": {
            "type": "object",
            "required": ["total_findings", "by_severity", "by_category", "by_component", "by_domain"],
            "additionalProperties": True,
            "properties": {
                "total_findings": {"type": "integer", "minimum": 0},
                "by_severity": {"type": "object", "additionalProperties": {"type": "integer"}},
                "by_category": {"type": "object", "additionalProperties": {"type": "integer"}},
                "by_component": {"type": "object", "additionalProperties": {"type": "integer"}},
                "by_domain": {"type": "object", "additionalProperties": {"type": "integer"}},
            },
        },
        "signal_availability": {"type": "object", "additionalProperties": {"type": "string"}},
        "sbom_summary": {"type": ["object", "null"], "additionalProperties": True},
        "dependency_summary": {"type": ["object", "null"], "additionalProperties": True},
        "supply_chain": {
            "type": ["object", "null"],
            "additionalProperties": {
                "type": "object",
                "additionalProperties": True,
                "properties": {
                    "image_signed": {},  # deliberately untyped — confirmed this session to legitimately be bool OR the string "unknown" depending on code path; verification_status is the field to trust, this one's kept for backward compat
                    "signature_verified": {"type": ["boolean", "string", "null"]},
                    "verification_notes": {"type": ["string", "null"]},
                    "verification_status": {"type": "string", "enum": VERIFICATION_STATUS_VALUES},
                },
            },
        },
        "schema_validation": {
            "type": ["object", "null"],
            "additionalProperties": True,
            "properties": {"valid": {"type": ["boolean", "null"]}},
        },
        "terraform_validation": {
            "type": ["object", "null"],
            "additionalProperties": True,
            "properties": {"valid": {"type": ["boolean", "null"]}},
        },
    },
}
