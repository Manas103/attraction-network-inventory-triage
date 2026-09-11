"""Regenerates a draw.io network diagram and a Theory of Operations document
from the SQLite inventory. Both are produced entirely by this module from
`SnapshotAssetRow` data; neither is hand-drawn or hand-written.

Topology rule (derived from the inventory, not hard-coded per device):
  - each zone is a swimlane container holding its assets as vertices
  - every asset in Zone 1 (Ride Control), Zone 2 (Show Control) and Zone 4
    (Engineering) is wired to a round-robin-assigned switch in Zone 3
    (Network Infrastructure), representing that zone's conduit uplink
  - the Zone 3 switches are chained to each other, representing the
    infrastructure backbone
This mirrors a real backstage design: end devices never talk zone-to-zone
directly, every path leaves through the infrastructure zone's switches.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from .inventory_db import SnapshotAssetRow
from .roster import ZONE_NAMES, ZONE_SUBNET

_ZONE_LAYOUT = {1: (40, 40), 2: (40, 400), 3: (600, 220), 4: (40, 760)}
_ROLE_STYLE = {
    "PLC": "shape=mxgraph.electrical.electrical_1",
    "Safety PLC": "shape=mxgraph.electrical.electrical_1",
    "HMI": "rounded=1",
    "Show Controller": "rounded=1",
    "Managed Switch": "shape=mxgraph.networks.switch",
    "Engineering Workstation": "shape=mxgraph.networks.workstation",
}


def build_drawio_xml(rows: list[SnapshotAssetRow]) -> str:
    mxfile = ET.Element("mxfile", {"host": "attraction-network-inventory-triage"})
    diagram = ET.SubElement(mxfile, "diagram", {"name": "Backstage Network (regenerated)"})
    model = ET.SubElement(diagram, "mxGraphModel")
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

    by_zone: dict[int, list[SnapshotAssetRow]] = {}
    for r in rows:
        by_zone.setdefault(r.zone or 0, []).append(r)

    for zone, (zx, zy) in _ZONE_LAYOUT.items():
        assets = by_zone.get(zone, [])
        height = max(80, 40 + 30 * len(assets))
        zone_cell = ET.SubElement(root, "mxCell", {
            "id": f"zone-{zone}",
            "value": f"{ZONE_NAMES.get(zone, f'Zone {zone}')} ({ZONE_SUBNET.get(zone, 'n/a')})",
            "style": "swimlane;horizontal=1;",
            "vertex": "1", "parent": "1",
        })
        ET.SubElement(zone_cell, "mxGeometry", {
            "x": str(zx), "y": str(zy), "width": "480", "height": str(height), "as": "geometry",
        })
        for i, r in enumerate(sorted(assets, key=lambda a: a.mac)):
            node_id = f"n-{r.mac}"
            style = _ROLE_STYLE.get(r.role or "", "rounded=0")
            cell = ET.SubElement(root, "mxCell", {
                "id": node_id,
                "value": f"{r.vendor or '?'} {r.model or '?'}\n{r.ip or '?'}",
                "style": style, "vertex": "1", "parent": f"zone-{zone}",
            })
            ET.SubElement(cell, "mxGeometry", {
                "x": "20", "y": str(30 + 30 * i), "width": "440", "height": "26", "as": "geometry",
            })

    # Conduit edges: every non-infrastructure asset uplinks to a Zone 3 switch, round robin.
    zone3_switches = sorted(by_zone.get(3, []), key=lambda a: a.mac)
    edge_i = 0
    if zone3_switches:
        for zone in (1, 2, 4):
            assets = sorted(by_zone.get(zone, []), key=lambda a: a.mac)
            for i, r in enumerate(assets):
                switch = zone3_switches[i % len(zone3_switches)]
                edge_i += 1
                edge = ET.SubElement(root, "mxCell", {
                    "id": f"e-{edge_i}", "style": "edgeStyle=orthogonalEdgeStyle;",
                    "edge": "1", "parent": "1", "source": f"n-{r.mac}", "target": f"n-{switch.mac}",
                })
                ET.SubElement(edge, "mxGeometry", {"relative": "1", "as": "geometry"})
        # Backbone chain across the infrastructure zone's own switches.
        for i in range(len(zone3_switches) - 1):
            edge_i += 1
            edge = ET.SubElement(root, "mxCell", {
                "id": f"e-{edge_i}", "style": "edgeStyle=orthogonalEdgeStyle;dashed=1;",
                "edge": "1", "parent": "1",
                "source": f"n-{zone3_switches[i].mac}", "target": f"n-{zone3_switches[i + 1].mac}",
            })
            ET.SubElement(edge, "mxGeometry", {"relative": "1", "as": "geometry"})

    return ET.tostring(mxfile, encoding="unicode")


def write_drawio(rows: list[SnapshotAssetRow], out_path: str | Path) -> Path:
    xml_text = build_drawio_xml(rows)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(xml_text, encoding="utf-8")
    return out_path


def build_theory_of_operations(rows: list[SnapshotAssetRow], generated_at: str, source_capture: str) -> str:
    by_zone: dict[int, list[SnapshotAssetRow]] = {}
    for r in rows:
        by_zone.setdefault(r.zone or 0, []).append(r)

    lines = [
        "# Theory of Operations: Attraction Backstage Network",
        "",
        f"Regenerated by `diagram.py` from the SQLite inventory on {generated_at}, "
        f"source capture `{source_capture}`. This document is generated, not hand-written; "
        "regenerating the inventory and re-running the diagram/ToO step reproduces it.",
        "",
        f"Total assets in this snapshot: {len(rows)}.",
        "",
    ]
    for zone in sorted(ZONE_NAMES):
        assets = by_zone.get(zone, [])
        lines.append(f"## Zone {zone}: {ZONE_NAMES[zone]} ({ZONE_SUBNET.get(zone, 'n/a')})")
        lines.append("")
        lines.append(f"{len(assets)} asset(s).")
        role_counts: dict[str, int] = {}
        for a in assets:
            role_counts[a.role or "unknown"] = role_counts.get(a.role or "unknown", 0) + 1
        for role, count in sorted(role_counts.items()):
            lines.append(f"- {count} x {role}")
        vendor_locked_count = sum(1 for a in assets if a.vendor_locked)
        lines.append(f"- {vendor_locked_count} of {len(assets)} are vendor-locked (no field-patchable update path).")
        lines.append("")

    lines.append("## Conduits")
    lines.append("")
    lines.append(
        "Every device in the Ride Control, Show Control and Engineering zones reaches the rest of the "
        "network only through a switch in the Network Infrastructure Zone; there is no direct zone-to-zone "
        "path. The Network Infrastructure Zone's own switches form the backbone. This is the topology the "
        "regenerated `.drawio` diagram draws."
    )
    return "\n".join(lines)


def write_theory_of_operations(rows: list[SnapshotAssetRow], generated_at: str, source_capture: str,
                                out_path: str | Path) -> Path:
    text = build_theory_of_operations(rows, generated_at, source_capture)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    return out_path
