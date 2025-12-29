#!/usr/bin/env python3
"""
Generate a minimal SPDX 2.3 SBOM from `cargo metadata`.

Usage:
    python scripts/generate_sbom.py [-o sbom.spdx.json]
"""
import argparse
import datetime
import json
import subprocess
import uuid
from pathlib import Path


def cargo_metadata() -> dict:
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked"]
    output = subprocess.check_output(cmd, text=True)
    return json.loads(output)


def spdx_id(name: str, version: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ".-_" else "-" for ch in name)
    return f"SPDXRef-Package-{safe}-{version}"


def build_packages(metadata: dict):
    packages = []
    id_map = {}
    for pkg in metadata["packages"]:
        pid = spdx_id(pkg["name"], pkg["version"])
        id_map[pkg["id"]] = pid
        packages.append(
            {
                "name": pkg["name"],
                "SPDXID": pid,
                "versionInfo": pkg["version"],
                "downloadLocation": f"crate://{pkg['name']}@{pkg['version']}",
                "licenseConcluded": pkg.get("license", "NOASSERTION") or "NOASSERTION",
                "filesAnalyzed": False,
                "supplier": "NOASSERTION",
            }
        )
    return packages, id_map


def build_relationships(resolve: dict, id_map: dict):
    rels = []
    for node in resolve.get("nodes", []):
        src = id_map.get(node["id"])
        if not src:
            continue
        for dep in node.get("deps", []):
            tgt = id_map.get(dep["pkg"])
            if tgt:
                rels.append(
                    {
                        "spdxElementId": src,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": tgt,
                    }
                )
    return rels


def main():
    parser = argparse.ArgumentParser(description="Generate SPDX SBOM from cargo metadata")
    parser.add_argument("-o", "--output", default="sbom.spdx.json", help="Output path")
    args = parser.parse_args()

    metadata = cargo_metadata()
    packages, id_map = build_packages(metadata)
    relationships = build_relationships(metadata["resolve"], id_map)

    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "usg-tacacs SBOM",
        "documentNamespace": f"urn:uuid:{uuid.uuid4()}",
        "creationInfo": {
            "created": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
            "creators": ["Tool: generate_sbom.py"],
        },
        "packages": packages,
        "relationships": relationships,
    }

    out_path = Path(args.output)
    out_path.write_text(json.dumps(doc, indent=2))
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
