#!/usr/bin/env python3
"""
SentinelOne - Export Policy JSON + CSV + Compliance Check

Exports SentinelOne group policies across tenants, sites, and accounts.
Outputs JSON files per group, CSV files per account, a global CSV, and
optionally a compliance report comparing against a baseline matrix.

Usage:
    python3 sentinelone_export.py --output ./output
    python3 sentinelone_export.py --output ./output --baseline ./policy_matrix.txt
    python3 sentinelone_export.py --output ./output --baseline ./baseline.csv --no-compliance

Environment variables (single tenant):
    S1_API_TOKEN   - SentinelOne API token
    S1_TENANT_URL  - Tenant URL (e.g. https://euce1-104.sentinelone.net/web/api/v2.1)

Environment variables (multi-tenant):
    S1_API_TOKENS  - JSON object mapping tenant name to API token
                     e.g. '{"euce1-104":"tok_a","euce1-109":"tok_b"}'
    S1_TENANT_URLS - JSON object mapping tenant name to base URL
                     e.g. '{"euce1-104":"https://euce1-104.sentinelone.net/web/api/v2.1"}'

Never hardcode tokens. Never commit tokens to version control.
"""

import argparse
import csv
import json
import logging
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG = logging.getLogger("sentinelone_export")

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "cyan": "\033[96m",
    "reset": "\033[0m",
}


def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_USE_COLOR = _supports_color()


def _c(text: str, color: str) -> str:
    if _USE_COLOR:
        return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"
    return text


def _log(level: str, msg: str, color: str | None = None):
    prefix = {"info": _c("INFO", "cyan"), "warn": _c("WARN", "yellow"), "error": _c("ERROR", "red")}.get(level, level.upper())
    if color:
        msg = _c(msg, color)
    print(f"  {prefix}  {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# HTTP Client
# ---------------------------------------------------------------------------

class SentinelOneClient:
    """Lightweight SentinelOne REST API client using only stdlib."""

    def __init__(self, base_url: str, api_token: str, timeout: int = 30, max_retries: int = 3):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.timeout = timeout
        self.max_retries = max_retries

        # Enforce TLS verification
        self._ssl_ctx = ssl.create_default_context()

    def _request(self, method: str, endpoint: str, params: dict | None = None) -> dict:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)

        headers = {"Authorization": f"ApiToken {self.api_token}", "Content-Type": "application/json"}
        req = urllib.request.Request(url, method=method, headers=headers)

        last_err = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx)
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                last_err = e
                body = ""
                try:
                    body = e.read().decode("utf-8", errors="replace")
                except Exception:
                    pass
                if e.code == 429:
                    retry_after = int(e.headers.get("Retry-After", 5))
                    _log("warn", f"Rate limited (429). Retrying in {retry_after}s (attempt {attempt}/{self.max_retries})")
                    time.sleep(retry_after)
                    continue
                if e.code >= 500:
                    wait = min(2 ** attempt, 10)
                    _log("warn", f"Server error {e.code}. Retrying in {wait}s (attempt {attempt}/{self.max_retries})")
                    time.sleep(wait)
                    continue
                _log("error", f"HTTP {e.code} for {method} {endpoint}: {body}")
                raise
            except (urllib.error.URLError, OSError) as e:
                last_err = e
                wait = min(2 ** attempt, 10)
                _log("warn", f"Network error: {e}. Retrying in {wait}s (attempt {attempt}/{self.max_retries})")
                time.sleep(wait)
                continue

        raise RuntimeError(f"Failed after {self.max_retries} attempts: {last_err}")

    def get(self, endpoint: str, params: dict | None = None) -> dict:
        return self._request("GET", endpoint, params)

    def get_accounts(self) -> list[dict]:
        return self.get("accounts", {"limit": 1000}).get("data", [])

    def get_groups(self) -> list[dict]:
        return self.get("groups", {"limit": 1000}).get("data", [])

    def get_sites(self, account_id: str) -> list[dict]:
        resp = self.get("sites", {"accountIds": account_id, "limit": 1000})
        return resp.get("data", {}).get("sites", [])

    def get_group_policy(self, group_id: str) -> dict:
        resp = self.get(f"groups/{group_id}/policy")
        return resp.get("data", {})


# ---------------------------------------------------------------------------
# File name sanitization
# ---------------------------------------------------------------------------

_UNSAFE_CHARS = re.compile(r'[\\/:*?"<>|]')


def safe_name(name: str) -> str:
    return _UNSAFE_CHARS.sub("_", name).strip().strip(".")


# ---------------------------------------------------------------------------
# Policy flattening (mapped settings for human-readable CSV)
# ---------------------------------------------------------------------------

def flatten_policy_settings(p: dict) -> list[dict]:
    """Return a list of {Section, Setting, Value} dicts from a policy object."""
    return [
        {"Section": "Protection Mode", "Setting": "Malicious Threats", "Value": p.get("mitigationMode")},
        {"Section": "Protection Mode", "Setting": "Suspicious Threats", "Value": p.get("mitigationModeSuspicious")},
        {"Section": "Protection Mode", "Setting": "Network Quarantine", "Value": p.get("networkQuarantineOn")},
        {"Section": "Protection Mode", "Setting": "Malicious Macro Mitigation", "Value": p.get("removeMacros")},

        {"Section": "Detection Engines", "Setting": "Reputation", "Value": _nested(p, "engines", "reputation")},
        {"Section": "Detection Engines", "Setting": "Static AI", "Value": _nested(p, "engines", "preExecution")},
        {"Section": "Detection Engines", "Setting": "Static AI - Suspicious", "Value": _nested(p, "engines", "preExecutionSuspicious")},
        {"Section": "Detection Engines", "Setting": "Behavioral AI - Executables", "Value": _nested(p, "engines", "executables")},
        {"Section": "Detection Engines", "Setting": "Documents, Scripts", "Value": _nested(p, "engines", "dataFiles")},
        {"Section": "Detection Engines", "Setting": "Lateral Movement", "Value": _nested(p, "engines", "lateralMovement")},
        {"Section": "Detection Engines", "Setting": "Anti Exploitation / Fileless", "Value": _nested(p, "engines", "exploits")},
        {"Section": "Detection Engines", "Setting": "Potentially Unwanted Applications", "Value": _nested(p, "engines", "pup")},

        {"Section": "Agent", "Setting": "Logging", "Value": p.get("agentLoggingOn")},
        {"Section": "Agent", "Setting": "Threat Notifications", "Value": p.get("agentNotification")},
        {"Section": "Agent", "Setting": "Show Agent UI", "Value": p.get("agentUiOn")},
        {"Section": "Agent", "Setting": "Enable Remote Shell", "Value": p.get("allowRemoteShell")},
        {"Section": "Agent", "Setting": "Anti Tamper", "Value": p.get("antiTamperingOn")},
        {"Section": "Agent", "Setting": "Auto Immune", "Value": p.get("autoImmuneOn")},
        {"Section": "Agent", "Setting": "Auto Decommission", "Value": p.get("autoDecommissionOn")},
        {"Section": "Agent", "Setting": "Offline Period Days", "Value": p.get("autoDecommissionDays")},
        {"Section": "Agent", "Setting": "Snapshots", "Value": p.get("snapshotsOn")},

        {"Section": "Agent UI", "Setting": "Show Support", "Value": _nested(p, "agentUi", "showSupport")},
        {"Section": "Agent UI", "Setting": "Show Quarantine Tab", "Value": _nested(p, "agentUi", "showQuarantineTab")},
        {"Section": "Agent UI", "Setting": "Show Device Tab", "Value": _nested(p, "agentUi", "showDeviceTab")},
        {"Section": "Agent UI", "Setting": "Show Suspicious Events", "Value": _nested(p, "agentUi", "showSuspicious")},

        {"Section": "Browser Extensions", "Setting": "Auto Install Extension", "Value": _nested(p, "iocAttributes", "autoInstallBrowserExtensions")},

        {"Section": "Binary Vault", "Setting": "Automatic File Upload", "Value": _nested(p, "autoFileUpload", "enabled")},
        {"Section": "Binary Vault", "Setting": "Include Benign Files", "Value": _nested(p, "autoFileUpload", "includeBenignFiles")},
        {"Section": "Binary Vault", "Setting": "Maximum File Size", "Value": _nested(p, "autoFileUpload", "maxFileSize")},
        {"Section": "Binary Vault", "Setting": "Daily Upload Limit", "Value": _nested(p, "autoFileUpload", "maxDailyFileUpload")},
        {"Section": "Binary Vault", "Setting": "Offline Cache Size", "Value": _nested(p, "autoFileUpload", "maxLocalDiskUsage")},

        {"Section": "Identity", "Setting": "Enabled", "Value": p.get("identityOn")},
        {"Section": "Identity", "Setting": "Reporting Level", "Value": p.get("identityEndpointReporting")},

        {"Section": "Forensics", "Setting": "Windows Enabled", "Value": _nested(p, "forensicsAutoTriggering", "windowsEnabled")},
        {"Section": "Forensics", "Setting": "MacOS Enabled", "Value": _nested(p, "forensicsAutoTriggering", "macosEnabled")},
        {"Section": "Forensics", "Setting": "Linux Enabled", "Value": _nested(p, "forensicsAutoTriggering", "linuxEnabled")},
    ]


def _nested(d: dict, *keys):
    """Safely traverse nested dicts."""
    for k in keys:
        if not isinstance(d, dict):
            return None
        d = d.get(k)
    return d


# ---------------------------------------------------------------------------
# Full CSV row (all raw fields)
# ---------------------------------------------------------------------------

def policy_to_full_row(account: dict, site: dict, group: dict, p: dict) -> dict:
    """Build the full flat CSV row matching the original PS1 output."""
    return {
        "AccountName": account.get("name"),
        "AccountId": account.get("id"),
        "SiteName": site.get("name"),
        "SiteId": site.get("id"),
        "GroupName": group.get("name"),
        "GroupId": group.get("id"),
        "PolicyName": group.get("name"),
        "PolicyId": group.get("id"),
        "InheritedFrom": p.get("inheritedFrom"),
        "AgentLoggingOn": p.get("agentLoggingOn"),
        "AgentNotification": p.get("agentNotification"),
        "AgentUiOn": p.get("agentUiOn"),
        "AllowRemoteShell": p.get("allowRemoteShell"),
        "AntiTamperingOn": p.get("antiTamperingOn"),
        "AutoImmuneOn": p.get("autoImmuneOn"),
        "AutoMitigationAction": p.get("autoMitigationAction"),
        "AutoDecommissionOn": p.get("autoDecommissionOn"),
        "AutoDecommissionDays": p.get("autoDecommissionDays"),
        "CloudValidationOn": p.get("cloudValidationOn"),
        "DriverBlocking": p.get("driverBlocking"),
        "IdentityOn": p.get("identityOn"),
        "IdentityEndpointReporting": p.get("identityEndpointReporting"),
        "IOC": p.get("ioc"),
        "InformationalAlertsOn": p.get("informationalAlertsOn"),
        "LogCollectorEnabled": p.get("logCollectorEnabled"),
        "MitigationMode": p.get("mitigationMode"),
        "MitigationModeSuspicious": p.get("mitigationModeSuspicious"),
        "MonitorOnExecute": p.get("monitorOnExecute"),
        "MonitorOnWrite": p.get("monitorOnWrite"),
        "NetworkProtectionInfra": p.get("networkProtectionInfra"),
        "NetworkQuarantineOn": p.get("networkQuarantineOn"),
        "RemoveMacros": p.get("removeMacros"),
        "RemoveMacrosMl": p.get("removeMacrosMl"),
        "ResearchOn": p.get("researchOn"),
        "ScanNewAgents": p.get("scanNewAgents"),
        "SignedDriverBlockingOn": p.get("signedDriverBlockingOn"),
        "SnapshotsOn": p.get("snapshotsOn"),
        "UnsignedDriverBlockingOn": p.get("unsignedDriverBlockingOn"),
        "ApplicationControl": _nested(p, "engines", "applicationControl"),
        "ApplicationDetection": _nested(p, "engines", "applicationDetection"),
        "DataFiles": _nested(p, "engines", "dataFiles"),
        "DriftDetection": _nested(p, "engines", "driftDetection"),
        "Executables": _nested(p, "engines", "executables"),
        "Exploits": _nested(p, "engines", "exploits"),
        "IDR": _nested(p, "engines", "idr"),
        "LateralMovement": _nested(p, "engines", "lateralMovement"),
        "NetworkProtection": _nested(p, "engines", "networkProtection"),
        "Penetration": _nested(p, "engines", "penetration"),
        "PreExecution": _nested(p, "engines", "preExecution"),
        "PreExecutionSuspicious": _nested(p, "engines", "preExecutionSuspicious"),
        "PUP": _nested(p, "engines", "pup"),
        "RemoteShellEngine": _nested(p, "engines", "remoteShell"),
        "Reputation": _nested(p, "engines", "reputation"),
        "PolicyCreatedAt": p.get("createdAt"),
        "PolicyUpdatedAt": p.get("updatedAt"),
    }


# ---------------------------------------------------------------------------
# CSV writers
# ---------------------------------------------------------------------------

_FULL_CSV_FIELDS = [
    "AccountName", "AccountId", "SiteName", "SiteId",
    "GroupName", "GroupId", "PolicyName", "PolicyId", "InheritedFrom",
    "AgentLoggingOn", "AgentNotification", "AgentUiOn",
    "AllowRemoteShell", "AntiTamperingOn",
    "AutoImmuneOn", "AutoMitigationAction",
    "AutoDecommissionOn", "AutoDecommissionDays",
    "CloudValidationOn", "DriverBlocking",
    "IdentityOn", "IdentityEndpointReporting",
    "IOC", "InformationalAlertsOn", "LogCollectorEnabled",
    "MitigationMode", "MitigationModeSuspicious",
    "MonitorOnExecute", "MonitorOnWrite",
    "NetworkProtectionInfra", "NetworkQuarantineOn",
    "RemoveMacros", "RemoveMacrosMl",
    "ResearchOn", "ScanNewAgents",
    "SignedDriverBlockingOn", "SnapshotsOn", "UnsignedDriverBlockingOn",
    "ApplicationControl", "ApplicationDetection", "DataFiles",
    "DriftDetection", "Executables", "Exploits", "IDR",
    "LateralMovement", "NetworkProtection", "Penetration",
    "PreExecution", "PreExecutionSuspicious", "PUP",
    "RemoteShellEngine", "Reputation",
    "PolicyCreatedAt", "PolicyUpdatedAt",
]


def write_csv(rows: list[dict], filepath: Path, fields: list[str] | None = None):
    if not rows:
        return
    if fields is None:
        fields = list(rows[0].keys())
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, delimiter=";", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Compliance checker
# ---------------------------------------------------------------------------

def load_baseline(filepath: Path) -> list[dict]:
    """Load policy_matrix baseline CSV."""
    rows = []
    with open(filepath, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=";")
        for row in reader:
            rows.append({
                "Section": row.get("Section", "").strip(),
                "Setting": row.get("Setting", "").strip(),
                "DefaultValue": row.get("Default Value", "").strip(),
                "ExpectedValue": row.get("ExpectedValue", "").strip(),
            })
    return rows


_VALUE_CANON = {
    "true": "Enabled", "enabled": "Enabled", "on": "Enabled", "1": "Enabled", "yes": "Enabled",
    "false": "Disabled", "disabled": "Disabled", "off": "Disabled", "0": "Disabled", "no": "Disabled",
    "disable": "Disabled",
    "protect": "Protect",
    "detect": "Detect",
}


def normalize_value(v) -> str:
    """Normalize a policy value to a canonical comparable string."""
    if v is None:
        return ""
    if isinstance(v, bool):
        return "Enabled" if v else "Disabled"
    if isinstance(v, str):
        low = v.strip().lower()
        if low in _VALUE_CANON:
            return _VALUE_CANON[low]
        return v.strip()
    if isinstance(v, (int, float)):
        if v == 1:
            return "Enabled"
        if v == 0:
            return "Disabled"
        return str(v)
    return str(v)


def check_compliance(
    mapped_rows: list[dict],
    baseline: list[dict],
    tenant_name: str,
) -> list[dict]:
    """Compare mapped CSV rows against baseline. Return non-compliant items."""
    results = []

    for bl in baseline:
        bl_section = bl["Section"]
        bl_setting = bl["Setting"]
        expected = bl["ExpectedValue"]
        if not expected:
            continue

        # Find matching rows in mapped export
        matching = [
            r for r in mapped_rows
            if r.get("Section") == bl_section and r.get("Setting") == bl_setting
        ]

        if not matching:
            results.append({
                "Tenant": tenant_name,
                "AccountName": "",
                "SiteName": "",
                "GroupName": "",
                "Section": bl_section,
                "Setting": bl_setting,
                "CurrentValue": "NOT FOUND IN EXPORT",
                "ExpectedValue": expected,
                "Status": "MISSING",
            })
            continue

        for row in matching:
            current = normalize_value(row.get("Value"))
            exp = normalize_value(expected)
            status = "COMPLIANT" if current == exp else "NON-COMPLIANT"
            results.append({
                "Tenant": tenant_name,
                "AccountName": row.get("AccountName", ""),
                "SiteName": row.get("SiteName", ""),
                "GroupName": row.get("GroupName", ""),
                "Section": bl_section,
                "Setting": bl_setting,
                "CurrentValue": current,
                "ExpectedValue": exp,
                "Status": status,
            })

    return results


# ---------------------------------------------------------------------------
# Main export logic
# ---------------------------------------------------------------------------

def export_tenant(
    client: SentinelOneClient,
    tenant_name: str,
    output_dir: Path,
    baseline: list[dict] | None,
    do_compliance: bool,
) -> tuple[list[dict], list[dict]]:
    """Export all policies for a single tenant. Returns (all_full_rows, compliance_results)."""
    tenant_dir = output_dir / safe_name(tenant_name)
    tenant_dir.mkdir(parents=True, exist_ok=True)

    _log("info", f"Fetching accounts for {tenant_name}...", "cyan")
    accounts = client.get_accounts()
    _log("info", f"Found {len(accounts)} accounts")

    _log("info", "Fetching all groups...", "cyan")
    all_groups = client.get_groups()
    _log("info", f"Found {len(all_groups)} groups")

    all_full_rows: list[dict] = []
    all_mapped_rows: list[dict] = []
    compliance_results: list[dict] = []
    errors = 0

    for account in accounts:
        account_name = account.get("name", "Unknown")
        account_id = account.get("id", "")
        safe_account = safe_name(account_name)
        account_dir = tenant_dir / safe_account
        account_dir.mkdir(parents=True, exist_ok=True)

        _log("info", f"ACCOUNT: {account_name}", "green")
        account_full_rows: list[dict] = []

        try:
            sites = client.get_sites(account_id)
        except Exception as e:
            _log("error", f"Failed to fetch sites for {account_name}: {e}")
            errors += 1
            continue

        _log("info", f"  Sites: {len(sites)}")

        for site in sites:
            site_name = site.get("name", "Unknown")
            site_id = site.get("id", "")

            _log("info", f"  SITE: {site_name}", "yellow")

            site_groups = [g for g in all_groups if g.get("siteId") == site_id]
            _log("info", f"    Groups: {len(site_groups)}")

            for group in site_groups:
                group_name = group.get("name", "Unknown")
                group_id = group.get("id", "")
                _log("info", f"      Policy: {group_name}")

                try:
                    policy = client.get_group_policy(group_id)
                except Exception as e:
                    _log("error", f"Failed to fetch policy for {group_name}: {e}")
                    errors += 1
                    continue

                safe_site = safe_name(site_name)
                safe_group = safe_name(group_name)

                # JSON export
                json_file = account_dir / f"{safe_site}_{safe_group}_{group_id}.json"
                with open(json_file, "w", encoding="utf-8") as f:
                    json.dump(policy, f, indent=2, ensure_ascii=False, default=str)

                # Full CSV row
                full_row = policy_to_full_row(account, site, group, policy)
                account_full_rows.append(full_row)
                all_full_rows.append(full_row)

                # Mapped settings row (for human-readable CSV + compliance)
                mapped = flatten_policy_settings(policy)
                for m in mapped:
                    m.update({
                        "AccountName": account_name,
                        "AccountId": account_id,
                        "SiteName": site_name,
                        "SiteId": site_id,
                        "GroupName": group_name,
                        "GroupId": group_id,
                    })
                all_mapped_rows.extend(mapped)

        # Account-level CSV (full fields)
        if account_full_rows:
            account_csv = account_dir / f"{safe_account}_Policies.csv"
            write_csv(account_full_rows, account_csv, _FULL_CSV_FIELDS)
            _log("info", f"    Wrote {len(account_full_rows)} rows to {account_csv.name}")

    # Global CSV per tenant
    global_csv = tenant_dir / f"{safe_name(tenant_name)}_AllPolicies.csv"
    write_csv(all_full_rows, global_csv, _FULL_CSV_FIELDS)
    _log("info", f"Wrote global CSV: {global_csv} ({len(all_full_rows)} rows)", "green")

    # Compliance check
    if do_compliance and baseline:
        compliance_results = check_compliance(all_mapped_rows, baseline, tenant_name)
        non_compliant = [r for r in compliance_results if r["Status"] == "NON-COMPLIANT"]
        _log("info", f"  Compliance: {len(non_compliant)} non-compliant / {len(compliance_results)} total checks")

    if errors:
        _log("warn", f"Completed with {errors} error(s)")

    return all_full_rows, compliance_results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="SentinelOne Policy Exporter + Compliance Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Single tenant
  S1_API_TOKEN=xxx S1_TENANT_URL=https://euce1-104.sentinelone.net/web/api/v2.1 \\
      python3 sentinelone_export.py --output ./output

  # With compliance check
  S1_API_TOKEN=xxx S1_TENANT_URL=https://euce1-104.sentinelone.net/web/api/v2.1 \\
      python3 sentinelone_export.py --output ./output --baseline ./policy_matrix.txt

  # Multi-tenant
  S1_API_TOKENS='{"t1":"tok_a","t2":"tok_b"}' \\
  S1_TENANT_URLS='{"t1":"https://t1.sentinelone.net/web/api/v2.1","t2":"https://t2.sentinelone.net/web/api/v2.1"}' \\
      python3 sentinelone_export.py --output ./output

  # Export only (skip compliance)
  python3 sentinelone_export.py --output ./output --no-compliance
""",
    )
    p.add_argument("--output", "-o", default=None, help="Output directory (default: ./SentinelOne_Policies)")
    p.add_argument("--baseline", "-b", default=None, help="Path to baseline CSV (e.g. policy_matrix.txt)")
    p.add_argument("--no-compliance", action="store_true", help="Skip compliance check even if --baseline is provided")
    p.add_argument("--timeout", type=int, default=None, help="HTTP request timeout in seconds (default: 30)")
    p.add_argument("--retries", type=int, default=None, help="Max retries per API call (default: 3)")
    p.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    return p.parse_args()


def resolve_cli_defaults(args):
    """Fill argparse defaults that are None from .env values, then hardcoded fallbacks."""
    args.output = args.output or os.environ.get("S1_OUTPUT_DIR") or "./SentinelOne_Policies"
    if args.baseline is None:
        args.baseline = os.environ.get("S1_BASELINE")
    if args.timeout is None:
        try:
            args.timeout = int(os.environ.get("S1_TIMEOUT", "30"))
        except ValueError:
            args.timeout = 30
    if args.retries is None:
        try:
            args.retries = int(os.environ.get("S1_RETRIES", "3"))
        except ValueError:
            args.retries = 3
    return args


def load_dotenv(path: str | os.PathLike = ".env") -> bool:
    """Load KEY=VALUE pairs from a .env file into os.environ.

    Real environment variables already set take precedence (file values are
    only used when the variable is unset). Returns True if a file was found.
    """
    env_file = Path(path).expanduser()
    if not env_file.is_file():
        return False

    loaded = 0
    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip("\"'").strip()
        if not key:
            continue
        if key not in os.environ:
            os.environ[key] = value
            loaded += 1
    _log("info", f"Loaded {loaded} variable(s) from {env_file}")
    return True


def load_tenants() -> dict[str, tuple[str, str]]:
    """Load tenant configurations from environment variables.
    Returns {tenant_name: (base_url, api_token)}.
    """
    tenants = {}

    # Multi-tenant mode
    tokens_json = os.environ.get("S1_API_TOKENS")
    urls_json = os.environ.get("S1_TENANT_URLS")

    if tokens_json and urls_json:
        try:
            tokens = json.loads(tokens_json)
            urls = json.loads(urls_json)
        except json.JSONDecodeError as e:
            _log("error", f"Failed to parse S1_API_TOKENS / S1_TENANT_URLS: {e}")
            sys.exit(1)

        for name in tokens:
            if name not in urls:
                _log("error", f"Tenant '{name}' has token but no URL in S1_TENANT_URLS")
                sys.exit(1)
            tenants[name] = (urls[name], tokens[name])

        return tenants

    # Single-tenant mode
    token = os.environ.get("S1_API_TOKEN")
    url = os.environ.get("S1_TENANT_URL")

    if token and url:
        tenants["default"] = (url, token)
        return tenants

    # No config found
    _log("error", "No tenant configuration found. Set environment variables:")
    _log("error", "  Single tenant:  S1_API_TOKEN + S1_TENANT_URL")
    _log("error", "  Multi-tenant:   S1_API_TOKENS + S1_TENANT_URLS (JSON objects)")
    _log("error", "Run with --help for examples.")
    sys.exit(1)


def main():
    args = parse_args()

    # Optional: load variables from a .env file next to the script (or --env)
    load_dotenv(os.environ.get("S1_DOTENV", ".env"))

    args = resolve_cli_defaults(args)

    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(message)s")

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load baseline if provided
    baseline = None
    if args.baseline and not args.no_compliance:
        baseline_path = Path(args.baseline)
        if not baseline_path.exists():
            _log("error", f"Baseline file not found: {baseline_path}")
            sys.exit(1)
        baseline = load_baseline(baseline_path)
        _log("info", f"Loaded baseline: {len(baseline)} settings")

    tenants = load_tenants()

    print(_c("=" * 60, "green"))
    print(_c("  SentinelOne Policy Export", "green"))
    print(_c(f"  Tenants: {len(tenants)}", "green"))
    print(_c(f"  Output:  {output_dir}", "green"))
    if baseline and not args.no_compliance:
        print(_c(f"  Baseline: {args.baseline}", "green"))
    print(_c("=" * 60, "green"))

    start = time.time()
    all_compliance: list[dict] = []

    for tenant_name, (base_url, api_token) in tenants.items():
        print()
        print(_c(f"--- Tenant: {tenant_name} ---", "cyan"))

        client = SentinelOneClient(
            base_url=base_url,
            api_token=api_token,
            timeout=args.timeout,
            max_retries=args.retries,
        )

        try:
            _, compliance = export_tenant(
                client=client,
                tenant_name=tenant_name,
                output_dir=output_dir,
                baseline=baseline,
                do_compliance=not args.no_compliance,
            )
            all_compliance.extend(compliance)
        except Exception as e:
            _log("error", f"Fatal error for tenant {tenant_name}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            continue

    # Comparison output: single file with only NON-COMPLIANT settings
    non_compliant = [r for r in all_compliance if r["Status"] == "NON-COMPLIANT"]
    if non_compliant:
        compliance_file = output_dir / "non_compliant_policies.csv"
        compliance_fields = ["Tenant", "AccountName", "SiteName", "GroupName", "Section", "Setting", "CurrentValue", "ExpectedValue"]
        write_csv(non_compliant, compliance_file, compliance_fields)

        print()
        print(_c(f"Non-compliant policies: {compliance_file}", "green"))
        print(_c(f"  Non-compliant settings: {len(non_compliant)}", "red"))
    else:
        print()
        print(_c("No non-compliant policies found.", "green"))

    elapsed = time.time() - start
    print()
    print(_c("=" * 60, "green"))
    print(_c("  EXPORT COMPLETED", "green"))
    print(_c(f"  Output: {output_dir}", "green"))
    print(_c(f"  Time:   {elapsed:.1f}s", "green"))
    print(_c("=" * 60, "green"))


if __name__ == "__main__":
    main()
