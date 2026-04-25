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


# ---------------------------------------------------------------------------
# Static intel fallback
#
# NVD's public API rate-limits to ~5 requests per 30s without an API key.
# For the famous CVEs below, we bundle the publicly documented CVSS v3 score
# and one-line description so the UI can render meaningful data even when NVD
# is throttled or offline. All values are public information from NVD itself;
# no private or company data is included.
#
# Format: cve_id -> (cvss_v3_score, severity, short_description, vendor, product)
# ---------------------------------------------------------------------------

STATIC_INTEL: Dict[str, Dict[str, object]] = {
    "CVE-2021-44228": {
        "cvss_v3_score": 10.0, "cvss_v3_severity": "CRITICAL",
        "description": "Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints (Log4Shell). Allows remote code execution.",
        "vendor": "apache", "product": "log4j",
    },
    "CVE-2021-45046": {
        "cvss_v3_score": 9.0, "cvss_v3_severity": "CRITICAL",
        "description": "Follow-up fix to Log4Shell; incomplete fix for CVE-2021-44228 in certain non-default configurations allows RCE.",
        "vendor": "apache", "product": "log4j",
    },
    "CVE-2022-22965": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Spring Framework RCE via data binding (Spring4Shell). Exploitable on JDK 9+ with specific app configurations.",
        "vendor": "vmware", "product": "spring_framework",
    },
    "CVE-2021-26855": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Microsoft Exchange Server SSRF (ProxyLogon). Allows unauthenticated remote attackers to execute arbitrary code.",
        "vendor": "microsoft", "product": "exchange_server",
    },
    "CVE-2021-34527": {
        "cvss_v3_score": 8.8, "cvss_v3_severity": "HIGH",
        "description": "Windows Print Spooler RCE (PrintNightmare). Allows privilege escalation and remote code execution.",
        "vendor": "microsoft", "product": "windows",
    },
    "CVE-2020-1472": {
        "cvss_v3_score": 10.0, "cvss_v3_severity": "CRITICAL",
        "description": "Netlogon elevation of privilege (Zerologon). Lets an unauthenticated attacker gain Domain Admin.",
        "vendor": "microsoft", "product": "windows",
    },
    "CVE-2019-0708": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Remote Desktop Services RCE (BlueKeep). Pre-auth wormable vulnerability in older Windows versions.",
        "vendor": "microsoft", "product": "windows",
    },
    "CVE-2017-5638": {
        "cvss_v3_score": 10.0, "cvss_v3_severity": "CRITICAL",
        "description": "Apache Struts 2 Jakarta Multipart parser RCE. Used in the 2017 Equifax breach.",
        "vendor": "apache", "product": "struts",
    },
    "CVE-2014-0160": {
        "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH",
        "description": "OpenSSL heartbeat extension buffer over-read (Heartbleed). Leaks memory including keys and credentials.",
        "vendor": "openssl", "product": "openssl",
    },
    "CVE-2022-26134": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Atlassian Confluence Server OGNL injection allowing unauthenticated RCE.",
        "vendor": "atlassian", "product": "confluence_server",
    },
    "CVE-2023-23397": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Microsoft Outlook elevation of privilege via crafted calendar invite leaking NTLM hashes.",
        "vendor": "microsoft", "product": "outlook",
    },
    "CVE-2023-4863": {
        "cvss_v3_score": 8.8, "cvss_v3_severity": "HIGH",
        "description": "libwebp heap buffer overflow in WebP image decoding; affects Chrome, Safari, Firefox and many apps.",
        "vendor": "google", "product": "libwebp",
    },
    "CVE-2023-34362": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Progress MOVEit Transfer SQL injection exploited by Cl0p ransomware group in mass data theft.",
        "vendor": "progress", "product": "moveit_transfer",
    },
    "CVE-2024-3094": {
        "cvss_v3_score": 10.0, "cvss_v3_severity": "CRITICAL",
        "description": "Malicious backdoor introduced in upstream XZ Utils (liblzma) versions 5.6.0/5.6.1; affects SSH via systemd.",
        "vendor": "tukaani", "product": "xz",
    },
    "CVE-2022-0847": {
        "cvss_v3_score": 7.8, "cvss_v3_severity": "HIGH",
        "description": "Linux kernel pipe flag handling (Dirty Pipe) allows privilege escalation by overwriting read-only files.",
        "vendor": "linux", "product": "linux_kernel",
    },
    "CVE-2021-3156": {
        "cvss_v3_score": 7.8, "cvss_v3_severity": "HIGH",
        "description": "sudo heap-based buffer overflow (Baron Samedit). Local privilege escalation to root.",
        "vendor": "sudo_project", "product": "sudo",
    },
    "CVE-2019-11043": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "PHP-FPM underflow in FastCGI handling allowing remote code execution under specific nginx configs.",
        "vendor": "php", "product": "php",
    },
    "CVE-2020-0601": {
        "cvss_v3_score": 8.1, "cvss_v3_severity": "HIGH",
        "description": "Windows CryptoAPI (Crypt32.dll) ECC certificate validation bypass (CurveBall). Allows signature spoofing.",
        "vendor": "microsoft", "product": "windows",
    },
    "CVE-2022-30190": {
        "cvss_v3_score": 7.8, "cvss_v3_severity": "HIGH",
        "description": "Microsoft Support Diagnostic Tool (MSDT) RCE via Office documents (Follina).",
        "vendor": "microsoft", "product": "windows",
    },
    "CVE-2021-42013": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Apache HTTP Server path traversal and RCE when mod_cgi is enabled.",
        "vendor": "apache", "product": "http_server",
    },
    "CVE-2022-1388": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "F5 BIG-IP iControl REST authentication bypass allowing unauthenticated RCE as root.",
        "vendor": "f5", "product": "big-ip",
    },
    "CVE-2023-20198": {
        "cvss_v3_score": 10.0, "cvss_v3_severity": "CRITICAL",
        "description": "Cisco IOS XE Web UI privilege escalation; creates admin accounts with unauthenticated access.",
        "vendor": "cisco", "product": "ios_xe",
    },
    "CVE-2024-21413": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Microsoft Outlook moniker link security feature bypass leading to NTLM credential leak and RCE.",
        "vendor": "microsoft", "product": "outlook",
    },
    "CVE-2021-21972": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "VMware vCenter Server vSphere Client unauthorized file upload leading to RCE.",
        "vendor": "vmware", "product": "vcenter_server",
    },
    "CVE-2018-7600": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Drupal core RCE via crafted request parameters (Drupalgeddon 2).",
        "vendor": "drupal", "product": "drupal",
    },
    "CVE-2019-19781": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Citrix ADC / Gateway (NetScaler) directory traversal leading to unauthenticated RCE.",
        "vendor": "citrix", "product": "application_delivery_controller",
    },
    "CVE-2022-24675": {
        "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH",
        "description": "Go standard library PEM decoding stack overflow in encoding/pem.",
        "vendor": "golang", "product": "go",
    },
    "CVE-2021-23017": {
        "cvss_v3_score": 7.7, "cvss_v3_severity": "HIGH",
        "description": "Nginx resolver off-by-one buffer write leading to potential RCE.",
        "vendor": "nginx", "product": "nginx",
    },
    "CVE-2021-3711": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "OpenSSL SM2 decryption buffer overflow affecting applications calling EVP_PKEY_decrypt.",
        "vendor": "openssl", "product": "openssl",
    },
    "CVE-2021-3712": {
        "cvss_v3_score": 7.4, "cvss_v3_severity": "HIGH",
        "description": "OpenSSL read buffer overrun in ASN.1 string handling leading to potential crash / info disclosure.",
        "vendor": "openssl", "product": "openssl",
    },
    "CVE-2022-37434": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "zlib heap-based buffer overflow in inflate.c when processing specially crafted gzip data.",
        "vendor": "zlib", "product": "zlib",
    },
    "CVE-2023-38545": {
        "cvss_v3_score": 8.8, "cvss_v3_severity": "HIGH",
        "description": "curl SOCKS5 heap buffer overflow when the hostname is longer than 255 bytes and resolution is delegated to the proxy.",
        "vendor": "haxx", "product": "curl",
    },
    "CVE-2023-44487": {
        "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH",
        "description": "HTTP/2 Rapid Reset DoS via rapidly opened and reset streams; exploited in record-breaking DDoS attacks.",
        "vendor": "ietf", "product": "http/2",
    },
    "CVE-2022-42889": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "Apache Commons Text variable interpolation RCE (Text4Shell) via script/dns/url lookups.",
        "vendor": "apache", "product": "commons_text",
    },
    "CVE-2021-44832": {
        "cvss_v3_score": 6.6, "cvss_v3_severity": "MEDIUM",
        "description": "Log4j JDBC Appender RCE when attacker controls the configuration file (less severe Log4Shell follow-up).",
        "vendor": "apache", "product": "log4j",
    },
    "CVE-2020-14145": {
        "cvss_v3_score": 5.9, "cvss_v3_severity": "MEDIUM",
        "description": "OpenSSH observable discrepancy enabling an attacker to identify target host keys.",
        "vendor": "openbsd", "product": "openssh",
    },
    "CVE-2022-23307": {
        "cvss_v3_score": 8.8, "cvss_v3_severity": "HIGH",
        "description": "Log4j 1.x Chainsaw component deserialization vulnerability.",
        "vendor": "apache", "product": "log4j",
    },
    "CVE-2019-16869": {
        "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH",
        "description": "Netty HTTP request smuggling via whitespace handling mismatches.",
        "vendor": "netty", "product": "netty",
    },
    "CVE-2022-25315": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "expat XML parser integer overflow in storeRawNames leading to memory corruption.",
        "vendor": "libexpat_project", "product": "libexpat",
    },
    "CVE-2021-36976": {
        "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH",
        "description": "libarchive use-after-free in copy_string during RAR5 decoding.",
        "vendor": "libarchive", "product": "libarchive",
    },
    "CVE-2022-0391": {
        "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH",
        "description": "Python urllib.parse URL parsing does not strip embedded newline characters, enabling SSRF/header injection.",
        "vendor": "python", "product": "python",
    },
    "CVE-2020-10531": {
        "cvss_v3_score": 8.8, "cvss_v3_severity": "HIGH",
        "description": "ICU integer overflow in the UnicodeString class leading to heap corruption.",
        "vendor": "icu-project", "product": "international_components_for_unicode",
    },
    "CVE-2021-23840": {
        "cvss_v3_score": 7.5, "cvss_v3_severity": "HIGH",
        "description": "OpenSSL integer overflow and bypass of AEAD tag checks in EVP_CipherUpdate.",
        "vendor": "openssl", "product": "openssl",
    },
    "CVE-2021-3450": {
        "cvss_v3_score": 7.4, "cvss_v3_severity": "HIGH",
        "description": "OpenSSL CA certificate check bypass via X509_V_FLAG_X509_STRICT handling error.",
        "vendor": "openssl", "product": "openssl",
    },
    "CVE-2022-29458": {
        "cvss_v3_score": 7.1, "cvss_v3_severity": "HIGH",
        "description": "ncurses segmentation fault in convert_strings in tinfo/read_entry.c.",
        "vendor": "gnu", "product": "ncurses",
    },
    "CVE-2022-1586": {
        "cvss_v3_score": 9.1, "cvss_v3_severity": "CRITICAL",
        "description": "PCRE2 out-of-bounds read in compile_xclass_matchingpath; affects many apps linking PCRE2.",
        "vendor": "pcre", "product": "pcre2",
    },
    "CVE-2019-12900": {
        "cvss_v3_score": 9.8, "cvss_v3_severity": "CRITICAL",
        "description": "bzip2 out-of-bounds write in BZ2_decompress on malformed streams.",
        "vendor": "bzip", "product": "bzip2",
    },
    "CVE-2020-8492": {
        "cvss_v3_score": 6.5, "cvss_v3_severity": "MEDIUM",
        "description": "Python urllib catastrophic backtracking in AbstractBasicAuthHandler regex enabling DoS.",
        "vendor": "python", "product": "python",
    },
}


def get_static_intel(cve_id: str) -> Dict[str, object]:
    """Return curated public intel for a famous CVE, or an empty dict.

    This exists so the UI has *something* to show even if NVD is rate-limited
    (HTTP 429), which is common when the free tier API is hit without an key.
    """
    return STATIC_INTEL.get(cve_id.strip().upper(), {})
