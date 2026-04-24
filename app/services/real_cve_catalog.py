"""Curated catalog of real, publicly documented CVEs.

These CVE identifiers are pulled from well-known open-source software
vulnerabilities. They are 100% public information available in NVD, EPSS,
and CISA KEV - no company data, no private disclosures.

Used by the synthetic data generator so that the AI-powered enrichment
pipeline can demonstrate real NVD/EPSS/CISA KEV responses instead of
returning empty data for fake CVE IDs.
"""

from __future__ import annotations

import random
from typing import Dict, List

from app.models import Severity

# Real, publicly documented CVEs grouped by approximate severity.
# All of these are on CISA KEV or have well-known public advisories.

CRITICAL_CVES: List[str] = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",  # Log4j follow-up
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2021-26855",  # ProxyLogon (Exchange)
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2020-1472",   # Zerologon
    "CVE-2019-0708",   # BlueKeep (RDP)
    "CVE-2017-5638",   # Apache Struts 2
    "CVE-2014-0160",   # Heartbleed (OpenSSL)
    "CVE-2022-26134",  # Confluence OGNL injection
    "CVE-2023-23397",  # Outlook privilege escalation
    "CVE-2023-4863",   # libwebp heap overflow
    "CVE-2023-34362",  # MOVEit SQLi
    "CVE-2024-3094",   # XZ backdoor
]

HIGH_CVES: List[str] = [
    "CVE-2022-0847",   # Dirty Pipe
    "CVE-2021-3156",   # Sudo Baron Samedit
    "CVE-2019-11043",  # PHP-FPM RCE
    "CVE-2020-0601",   # CurveBall (Crypto API)
    "CVE-2022-30190",  # Follina
    "CVE-2021-42013",  # Apache path traversal
    "CVE-2022-1388",   # F5 BIG-IP iControl
    "CVE-2023-20198",  # Cisco IOS XE
    "CVE-2024-21413",  # Outlook moniker
    "CVE-2021-21972",  # vCenter RCE
    "CVE-2018-7600",   # Drupalgeddon2
    "CVE-2019-19781",  # Citrix ADC
]

MEDIUM_CVES: List[str] = [
    "CVE-2022-24675",  # Go stdlib
    "CVE-2021-23017",  # Nginx resolver
    "CVE-2021-3711",   # OpenSSL buffer overflow
    "CVE-2021-3712",   # OpenSSL read buffer
    "CVE-2022-37434",  # zlib heap overflow
    "CVE-2023-38545",  # curl SOCKS5 heap overflow
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2022-42889",  # Apache Commons Text
    "CVE-2021-44832",  # Log4j JDBC
    "CVE-2020-14145",  # OpenSSH observable discrepancy
    "CVE-2022-23307",  # Log4j 1.x chainsaw
    "CVE-2019-16869",  # Netty HTTP smuggling
]

LOW_CVES: List[str] = [
    "CVE-2022-25315",  # expat integer overflow
    "CVE-2021-36976",  # libarchive
    "CVE-2022-0391",   # Python urllib
    "CVE-2020-10531",  # ICU int overflow
    "CVE-2021-23840",  # OpenSSL integer overflow
    "CVE-2021-3450",   # OpenSSL CA cert check
    "CVE-2022-29458",  # ncurses
    "CVE-2022-1586",   # PCRE2
    "CVE-2019-12900",  # bzip2
    "CVE-2020-8492",   # Python urllib DoS
]


SEVERITY_POOLS: Dict[Severity, List[str]] = {
    Severity.CRITICAL: CRITICAL_CVES,
    Severity.HIGH: HIGH_CVES,
    Severity.MEDIUM: MEDIUM_CVES,
    Severity.LOW: LOW_CVES,
}


def pick_cve_for_severity(severity: Severity) -> str:
    """Return a real public CVE id whose severity roughly matches.

    Falls back to a random pool if the severity is unknown.
    """
    pool = SEVERITY_POOLS.get(severity)
    if not pool:
        pool = HIGH_CVES
    return random.choice(pool)


def all_cves() -> List[str]:
    """Return all CVEs in the catalog (useful for pre-warming the cache)."""
    all_items: List[str] = []
    for pool in SEVERITY_POOLS.values():
        all_items.extend(pool)
    return all_items
