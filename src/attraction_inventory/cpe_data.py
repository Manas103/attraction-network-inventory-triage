"""Bundled offline CPE dictionary subset and CPE-to-CVE map.

This is NOT the live NVD feed. It is a small, hand-picked subset of real
entries pulled from the public NVD CVE API (services.nvd.nist.gov) once,
during development of this project, then embedded here as a static
snapshot so the matchers run fully offline and deterministically. Every
CPE string and CVE id below is real and independently verifiable against
NVD; the fictional 120-asset fleet was built to reuse these exact
vendor/product identifiers so the matching stage has something real to
match against, rather than matching synthetic vendors against synthetic
CVEs (which would prove nothing).

Coverage is intentionally partial: Belden/Hirschmann switches and the
Rockwell/Alcorn McBride show-control gear each have real entries, but some
product lines in the fleet (e.g. Alcorn McBride's V4X) have no published
NVD CVE, and that is reported honestly as "0 CVEs found" rather than
invented.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CpeEntry:
    cpe23_ids: tuple[str, ...]  # one asset model can map to more than one real NVD CPE (hardware + firmware)
    vendor: str      # normalized vendor key as it appears in NVD's CPE vendor field
    product: str      # normalized product key as it appears in NVD's CPE product field
    display_vendor: str
    display_product: str  # must equal exactly what fingerprint.py reports as asset.model for this device

    @property
    def cpe23(self) -> str:
        """Primary (first) CPE id, used for display."""
        return self.cpe23_ids[0]


@dataclass(frozen=True)
class CveRecord:
    cve_id: str
    description: str
    cpe23_matches: tuple[str, ...]


# Real CPE dictionary subset (vendor/product identifiers as published by NVD).
# display_product is deliberately set to match what fingerprint.py extracts as
# asset.model for that device (the CIP productName field, the Modbus
# ModelName device-identification object, or the mDNS-style "model" key),
# because the matchers key off the device's own self-reported model string,
# not off NVD's often more specific firmware-version-qualified product name.
CPE_DICTIONARY: list[CpeEntry] = [
    CpeEntry(("cpe:2.3:h:rockwellautomation:1756-enbt:-:*:*:*:*:*:*:*",),
             "rockwellautomation", "1756-enbt", "Rockwell Automation", "1756-ENBT/A ControlLogix EtherNet/IP Bridge"),
    CpeEntry(("cpe:2.3:o:rockwellautomation:panelview_plus_6_700-1500_firmware:*:*:*:*:*:*:*:*",),
             "rockwellautomation", "panelview_plus_6_700-1500_firmware", "Rockwell Automation", "PanelView Plus 6 700"),
    CpeEntry(("cpe:2.3:o:rockwellautomation:panelview_5510_firmware:*:*:*:*:*:*:*:*",),
             "rockwellautomation", "panelview_5510_firmware", "Rockwell Automation", "PanelView 5510"),
    CpeEntry(("cpe:2.3:h:schneider-electric:bmxnoe0100:-:*:*:*:*:*:*:*",
              "cpe:2.3:o:schneider-electric:modicon_m340_bmxp342020_firmware:2.8:*:*:*:*:*:*:*"),
             "schneider-electric", "bmxnoe0100", "Schneider Electric", "Modicon M340"),
    CpeEntry(("cpe:2.3:o:schneider-electric:bmxnor0200_firmware:-:*:*:*:*:*:*:*",),
             "schneider-electric", "bmxnor0200_firmware", "Schneider Electric", "Modicon M340 Safety"),
    CpeEntry(("cpe:2.3:h:belden:hirschmann_rs20-0900mmm2tdau:-:*:*:*:*:*:*:*",),
             "belden", "hirschmann_rs20-0900mmm2tdau", "Belden/Hirschmann", "RS20 Managed Switch"),
    CpeEntry(("cpe:2.3:h:belden:hirschmann_rsr20:-:*:*:*:*:*:*:*",),
             "belden", "hirschmann_rsr20", "Belden/Hirschmann", "RSR20 Managed Switch"),
    CpeEntry(("cpe:2.3:h:belden:hirschmann_octopus_16m:-:*:*:*:*:*:*:*",),
             "belden", "hirschmann_octopus_16m", "Belden/Hirschmann", "OCTOPUS 16M Managed Switch"),
]

# Real CVE records, each linked to the real CPE match criteria NVD publishes for it.
CVE_RECORDS: list[CveRecord] = [
    CveRecord("CVE-2012-6435",
              "Denial of service: affected products enter a CPU fault state on receipt of a valid but "
              "unexpected CIP message instructing the CPU to stop logic execution.",
              ("cpe:2.3:h:rockwellautomation:1756-enbt:-:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2012-6436",
              "Buffer overflow via malformed CIP packets sent to the EtherNet/IP port causes a CPU crash "
              "and disrupts communication.",
              ("cpe:2.3:h:rockwellautomation:1756-enbt:-:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2012-6437",
              "Improper authentication allows remote firmware upload without verification.",
              ("cpe:2.3:h:rockwellautomation:1756-enbt:-:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2017-7914",
              "Missing authorization allows an unauthenticated remote attacker to reach protected "
              "functionality on PanelView Plus 6 700-1500 terminals.",
              ("cpe:2.3:o:rockwellautomation:panelview_plus_6_700-1500_firmware:*:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2019-10970",
              "Unauthenticated remote attacker gains root-level access to the PanelView 5510 file system.",
              ("cpe:2.3:o:rockwellautomation:panelview_5510_firmware:*:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2017-6017",
              "Resource exhaustion: crafted packets sent to Modicon M340 cause the device to freeze, "
              "requiring a physical power-cycle to recover.",
              ("cpe:2.3:o:schneider-electric:modicon_m340_bmxp342020_firmware:2.8:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2018-7241",
              "Hard-coded accounts exist in Modicon M340 and BMXNOR0200 communication modules across all "
              "firmware versions.",
              ("cpe:2.3:o:schneider-electric:bmxnor0200_firmware:-:*:*:*:*:*:*:*",
               "cpe:2.3:o:schneider-electric:modicon_m340_bmxp342020_firmware:2.8:*:*:*:*:*:*:*")),
    CveRecord("CVE-2018-7242",
              "Weak hash algorithms in the password-encryption mechanism allow hash-collision attacks "
              "on BMXNOR0200 controllers.",
              ("cpe:2.3:o:schneider-electric:bmxnor0200_firmware:-:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2016-2509",
              "The password-sync feature on Belden/Hirschmann Classic Platform switches (including RS20) "
              "sets the SNMP community string to the same value as the administrator password.",
              ("cpe:2.3:h:belden:hirschmann_rs20-0900mmm2tdau:-:*:*:*:*:*:*:*",)),
    CveRecord("CVE-2018-5461",
              "Inadequate encryption strength in the web interface enables a man-in-the-middle attack on "
              "Classic Platform switches including RS, RSR and OCTOPUS models.",
              ("cpe:2.3:h:belden:hirschmann_rs20-0900mmm2tdau:-:*:*:*:*:*:*:*",
               "cpe:2.3:h:belden:hirschmann_rsr20:-:*:*:*:*:*:*:*",
               "cpe:2.3:h:belden:hirschmann_octopus_16m:-:*:*:*:*:*:*:*")),
]


def cve_lookup_by_cpe() -> dict[str, list[CveRecord]]:
    index: dict[str, list[CveRecord]] = {}
    for record in CVE_RECORDS:
        for cpe in record.cpe23_matches:
            index.setdefault(cpe, []).append(record)
    return index
