#!/usr/bin/env python3
"""
Normalizes a Syft SBOM (SPDX-JSON format, via `syft <image> -o spdx-json`,
or the anchore/sbom-action `format: spdx-json` output) into a simplified
package-inventory schema:
{tool, component, package_name, version, ecosystem, purl, license}

DESIGN NOTE: this is intentionally a *different* schema from the security
findings normalizers (normalize_codeql.py, normalize_snyk.py, etc.) and is
NOT intended to be passed into merge_findings.py. An SBOM entry describes
"this package exists in the image" — it has no severity, no confidence,
nothing actionable on its own. Cramming ~100-300 packages per image into
the findings schema would either require faking those fields or burying
the small number of real vulnerabilities/secrets findings under a wall of
inventory noise. Keep this as a separate artifact; if vulnerability
scanning of the SBOM itself is wanted later (e.g. piping it through
Grype), that's a distinct tool/normalizer, not a reason to change this
schema.

Usage:
    normalize_sbom.py <output.json> <spdx_json_file> [component_label]

component_label is an optional free-text tag (e.g. "backend", "frontend")
to identify which image this SBOM came from once multiple normalized SBOMs
exist side by side.
"""
import json
import sys


def extract_purl(package):
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "purl":
            return ref.get("referenceLocator")
    return None


def extract_ecosystem(purl):
    """Derive package ecosystem from a purl's scheme, e.g.
    'pkg:npm/lodash@4.17.21' -> 'npm', 'pkg:deb/debian/openssl@3.0.13' -> 'deb'."""
    if not purl or not purl.startswith("pkg:"):
        return "unknown"
    remainder = purl[len("pkg:"):]
    return remainder.split("/", 1)[0] if "/" in remainder else remainder


def extract_license(package):
    """Prefer licenseConcluded over licenseDeclared; SPDX uses the literal
    string 'NOASSERTION' rather than omitting the field when unknown."""
    for key in ("licenseConcluded", "licenseDeclared"):
        value = package.get(key)
        if value and value != "NOASSERTION":
            return value
    return "unknown"


def normalize_spdx(spdx_path, component_label):
    findings = []
    try:
        with open(spdx_path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"WARNING: could not read {spdx_path}: {e}", file=sys.stderr)
        return findings

    for package in data.get("packages", []):
        name = package.get("name", "unknown")
        # SPDX root document is itself listed as a "package" describing the
        # scanned image/filesystem as a whole — skip it, it's not a real
        # dependency.
        if package.get("SPDXID") == "SPDXRef-DOCUMENT" or name == data.get("name"):
            continue

        version = package.get("versionInfo", "unknown")
        purl = extract_purl(package)
        ecosystem = extract_ecosystem(purl)
        license_ = extract_license(package)

        findings.append({
            "tool": "syft",
            "component": component_label,
            "package_name": name,
            "version": version,
            "ecosystem": ecosystem,
            "purl": purl,
            "license": license_,
        })

    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: normalize_sbom.py <output.json> <spdx_json_file> [component_label]", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    spdx_path = sys.argv[2]
    component_label = sys.argv[3] if len(sys.argv) > 3 else None

    packages = normalize_spdx(spdx_path, component_label)

    with open(output_path, "w") as f:
        json.dump(packages, f, indent=2)

    print(f"Normalized {len(packages)} SBOM packages -> {output_path}")


if __name__ == "__main__":
    main()