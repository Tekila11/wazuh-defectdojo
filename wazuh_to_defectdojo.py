#!/usr/bin/env python3
"""
Wazuh → DefectDojo enriched import script

Queries OpenSearch (Wazuh Indexer) for all vulnerability findings,
groups them by agent (one product per machine), and imports into
DefectDojo with full field enrichment.

Product structure in DefectDojo:
    Product Type: <Wazuh agent group>  (e.g. "Windows Servers", "Linux Servers")
    └── Product: <agent name>          (e.g. "APP-SRV-01", "mon-srv-01")
        └── Engagement: Wazuh Vulnerability Scan (recurring CI/CD)
            └── Test (reused across runs via state file)
                └── Findings (endpoints = hostname + IP from Wazuh API)

Enriched fields:
    - host.os.full                          → OS version in description
    - package.path / license / architecture → package context
    - vulnerability.score.temporal/env      → CVSS fallback
    - vulnerability.scanner.condition       → fix guidance
    - vulnerability.scanner.source          → data source
    - wazuh.manager.name / agent.version    → infrastructure context
    - agent IP from Wazuh API /agents       → second endpoint alongside hostname

State file (state.json): keyed by agent ID (stable across renames).
    {
      "006": {"test_id": 4, "name": "APP-SRV-01"},
      ...
    }
Subsequent runs use reimport-scan/ to update the existing test.
If an agent is disconnected (absent from Wazuh API), its import is skipped
to avoid closing valid findings.

Run daily via cron:
    0 6 * * * cd /opt/scripts/wazuh-to-defectdojo && source .env && python3 wazuh_to_defectdojo.py
"""

import json
import logging
import os
import tempfile
from collections import defaultdict
from datetime import date
from pathlib import Path

import requests
import urllib3
from opensearchpy import OpenSearch, RequestsHttpConnection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

OPENSEARCH_HOST = os.environ["OPENSEARCH_HOST"]
OPENSEARCH_PORT = int(os.environ.get("OPENSEARCH_PORT", "9200"))
OPENSEARCH_USER = os.environ["OPENSEARCH_USER"]
OPENSEARCH_PASS = os.environ["OPENSEARCH_PASS"]

WAZUH_API_URL   = os.environ.get("WAZUH_API_URL", "")
WAZUH_API_USER  = os.environ.get("WAZUH_API_USER", "")
WAZUH_API_PASS  = os.environ.get("WAZUH_API_PASS", "")

DD_URL          = os.environ["DD_URL"]
DD_TOKEN        = os.environ["DD_TOKEN"]
DD_MIN_SEVERITY = os.environ.get("DD_MIN_SEVERITY", "Low")

STATE_FILE      = Path(os.environ.get("STATE_FILE", "state.json"))

SKIP_SEVERITIES = {"untriaged", "none", "-", "info"}
VULN_INDEX      = "wazuh-states-vulnerabilities-*"
SCROLL_SIZE     = 1000
SCROLL_TTL      = "3m"

SEVERITY_MAP = {
    "critical": "Critical",
    "high":     "High",
    "medium":   "Medium",
    "low":      "Low",
    "info":     "Info",
    "none":     "Info",
    "-":        "Info",
}

DEFAULT_PRODUCT_TYPE = "Endpoints"  # used when agent group is "default" or unknown


# ── OpenSearch ────────────────────────────────────────────────────────────────

def get_client() -> OpenSearch:
    return OpenSearch(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASS),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False,
        connection_class=RequestsHttpConnection,
    )


def iter_index(client: OpenSearch, index: str):
    """Scroll through all documents in an index."""
    resp = client.search(
        index=index,
        scroll=SCROLL_TTL,
        body={"size": SCROLL_SIZE, "query": {"match_all": {}}},
    )
    scroll_id = resp.get("_scroll_id")
    if not scroll_id:
        for hit in resp.get("hits", {}).get("hits", []):
            yield hit["_source"]
        return
    hits = resp["hits"]["hits"]
    while hits:
        for hit in hits:
            yield hit["_source"]
        resp = client.scroll(scroll_id=scroll_id, scroll=SCROLL_TTL)
        scroll_id = resp.get("_scroll_id", scroll_id)
        hits = resp["hits"]["hits"]
    try:
        client.clear_scroll(scroll_id=scroll_id)
    except Exception:
        pass  # 403 from wazuh-readonly role missing scroll/clear permission — non-critical


# ── Wazuh API ─────────────────────────────────────────────────────────────────

def build_agent_cache() -> dict[str, dict]:
    """Return {agent_id: {"name": ..., "ip": ..., "group": ..., "status": ...}}."""
    cache: dict[str, dict] = {}
    if not WAZUH_API_URL or not WAZUH_API_USER or not WAZUH_API_PASS:
        log.info("Wazuh API not configured — skipping agent cache")
        return cache
    try:
        r = requests.post(
            f"{WAZUH_API_URL}/security/user/authenticate?raw=true",
            auth=(WAZUH_API_USER, WAZUH_API_PASS),
            verify=False,
            timeout=15,
        )
        r.raise_for_status()
        token = r.text.strip()

        offset = 0
        limit  = 500
        while True:
            r = requests.get(
                f"{WAZUH_API_URL}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "offset": offset, "pretty": "true"},
                verify=False,
                timeout=30,
            )
            r.raise_for_status()
            data  = r.json().get("data", {})
            items = data.get("affected_items", [])
            for agent in items:
                agent_id = str(agent.get("id", "")).strip()
                name     = agent.get("name", "").strip()
                ip       = agent.get("ip", "").strip()
                groups   = agent.get("group", ["default"])
                group    = groups[0] if groups else "default"
                status   = agent.get("status", "")
                if agent_id:
                    cache[agent_id] = {
                        "name":   name,
                        "ip":     ip if ip not in ("any", "unknown", "") else None,
                        "group":  group,
                        "status": status,
                    }
            if len(items) < limit:
                break
            offset += limit
    except Exception as exc:
        log.warning(f"Could not build agent cache from Wazuh API: {exc}")
    log.info(f"Agent cache: {len(cache)} entries")
    return cache


# ── Finding builder ───────────────────────────────────────────────────────────

def build_finding(doc: dict, agent_cache: dict[str, dict]) -> dict | None:
    vuln    = doc.get("vulnerability", {})
    pkg     = doc.get("package", {})
    agent   = doc.get("agent", {})
    os_info = doc.get("host", {}).get("os", {})
    scanner = vuln.get("scanner", {})
    wazuh   = doc.get("wazuh", {})

    cve      = vuln.get("id", "")
    severity = vuln.get("severity", "").lower()
    pkg_name = pkg.get("name", "")
    pkg_ver  = pkg.get("version", "")

    if not cve or not pkg_name:
        return None
    if severity in SKIP_SEVERITIES:
        return None

    score = (
        vuln.get("score", {}).get("base")
        or vuln.get("score", {}).get("temporal")
        or vuln.get("score", {}).get("environmental")
    )

    detected  = vuln.get("detected_at", "")[:10] or date.today().isoformat()
    published = vuln.get("published_at", "")[:10] or None

    desc_parts = [vuln.get("description", "No description available."), ""]
    if os_info.get("full"):
        desc_parts.append(f"**OS:** {os_info['full']}")
    if pkg.get("path"):
        desc_parts.append(f"**Package path:** {pkg['path']}")
    if pkg.get("license"):
        desc_parts.append(f"**License:** {pkg['license']}")
    if pkg.get("architecture"):
        desc_parts.append(f"**Architecture:** {pkg['architecture']}")
    if scanner.get("condition"):
        desc_parts.append(f"**Fix condition:** {scanner['condition']}")
    if scanner.get("source"):
        desc_parts.append(f"**Source:** {scanner['source']}")
    if wazuh.get("manager", {}).get("name"):
        desc_parts.append(f"**Wazuh manager:** {wazuh['manager']['name']}")
    if agent.get("version"):
        desc_parts.append(f"**Agent version:** {agent['version']}")

    agent_id   = str(agent.get("id", "")).strip()
    agent_info = agent_cache.get(agent_id, {})
    # Use current name from Wazuh API (handles renames); fall back to doc
    agent_name = agent_info.get("name") or agent.get("name") or agent_id or "unknown"
    # Use IP as endpoint for cross-scanner correlation; fall back to hostname
    endpoints = [{"host": agent_name}]

    return {
        "title":             f"{cve} in {pkg_name} {pkg_ver}",
        "date":              detected,
        "publish_date":      published,
        "severity":          SEVERITY_MAP.get(severity, "Info"),
        "description":       "\n".join(desc_parts),
        "mitigation":        vuln.get("status", ""),
        "impact":            scanner.get("condition", ""),
        "component_name":    pkg_name,
        "component_version": pkg_ver,
        "cvssv3_score":      score,
        "references":        vuln.get("reference", ""),
        "cve":               cve,
        "vuln_id_from_tool": cve,
        "endpoints":         endpoints,
        "active":            True,
        "verified":          False,
    }


def agent_to_product_type(agent_id: str, agent_cache: dict[str, dict]) -> str:
    """Wazuh group name → DefectDojo product type. 'default' → Endpoints."""
    group = agent_cache.get(agent_id, {}).get("group", "default")
    if not group or group == "default":
        return DEFAULT_PRODUCT_TYPE
    return group


# ── State file ────────────────────────────────────────────────────────────────
# Format: {agent_id: {"test_id": int, "name": str}}

def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


# ── DefectDojo client ─────────────────────────────────────────────────────────

class DefectDojoClient:
    def __init__(self, url: str, token: str):
        self.base    = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Token {token}", "Accept": "application/json"})
        self.session.verify = False

    def _get(self, path: str, params: dict = None) -> dict:
        r = self.session.get(f"{self.base}/api/v2{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, timeout: int = 60, **kwargs) -> dict:
        r = self.session.post(f"{self.base}/api/v2{path}", timeout=timeout, **kwargs)
        r.raise_for_status()
        return r.json()

    def get_product_type_id(self, name: str) -> int:
        results = self._get("/product_types/", params={"name": name}).get("results", [])
        if results:
            return results[0]["id"]
        return self._post("/product_types/", json={"name": name})["id"]

    AUDIT_TYPE_KEYWORDS = {"audit", "pentest", "assessment", "one-time"}

    def _is_audit_product(self, product_id: int) -> bool:
        try:
            p = self._get(f"/products/{product_id}/")
            type_id = p.get("prod_type")
            if not type_id:
                return False
            pt = self._get(f"/product_types/{type_id}/")
            return any(kw in pt.get("name", "").lower() for kw in self.AUDIT_TYPE_KEYWORDS)
        except Exception:
            return False

    def find_product_by_endpoint(self, ip_str: str, hostname: str) -> int | None:
        """Return product ID by searching endpoints for IP or hostname, skipping audit products."""
        for host_val in filter(None, [ip_str, hostname]):
            results = self._get("/endpoints/", params={"host": host_val, "limit": 10}).get("results", [])
            for ep in results:
                pid = ep.get("product")
                if not pid:
                    continue
                if self._is_audit_product(pid):
                    log.info(f"Skipping audit product {pid} for {host_val}")
                    continue
                log.info(f"Found existing product {pid} via endpoint {host_val}")
                return pid
        return None

    def get_or_create_product(self, name: str, type_id: int, ip_str: str = "") -> int:
        # Endpoint-based lookup first — finds products created by Kaspersky or other scanners
        pid = self.find_product_by_endpoint(ip_str, name)
        if pid:
            return pid

        results = self._get("/products/", params={"name": name}).get("results", [])
        if results:
            return results[0]["id"]
        log.info(f"Creating product: {name}")
        return self._post("/products/", json={
            "name":        name,
            "description": f"Wazuh vulnerability findings — {name}",
            "prod_type":   type_id,
        })["id"]

    def rename_product(self, product_id: int, new_name: str) -> None:
        self.session.patch(
            f"{self.base}/api/v2/products/{product_id}/",
            json={"name": new_name},
            timeout=30,
        ).raise_for_status()

    def get_existing_test_id(self, engagement_id: int) -> int | None:
        """Return the most recent test ID for an engagement, or None."""
        results = self._get("/tests/", params={
            "engagement": engagement_id,
            "scan_type":  "Generic Findings Import",
            "limit":      1,
        }).get("results", [])
        return results[0]["id"] if results else None

    def get_or_create_engagement(self, product_id: int) -> int:
        results = self._get("/engagements/", params={
            "product":         product_id,
            "name":            "Wazuh Vulnerability Scan",
            "engagement_type": "CI/CD",
        }).get("results", [])
        if results:
            return results[0]["id"]
        log.info(f"Creating engagement for product {product_id}")
        return self._post("/engagements/", json={
            "name":            "Wazuh Vulnerability Scan",
            "product":         product_id,
            "engagement_type": "CI/CD",
            "status":          "In Progress",
            "target_start":    date.today().isoformat(),
            "target_end":      "2099-12-31",
        })["id"]

    def import_findings(self, engagement_id: int, findings: list,
                        tmpdir: str, test_id: int | None) -> tuple:
        tmp = Path(tmpdir) / f"findings_{engagement_id}.json"
        tmp.write_text(json.dumps({"findings": findings}, default=str))

        common = {
            "scan_type":        "Generic Findings Import",
            "minimum_severity": DD_MIN_SEVERITY,
            "active":           "true",
            "verified":         "false",
            "skip_duplicates":  "true",
            "tags":             "wazuh",
        }

        with open(tmp, "rb") as f:
            if test_id:
                log.info(f"  reimport-scan (test_id={test_id})")
                result = self._post(
                    "/reimport-scan/",
                    timeout=600,
                    files={"file": ("findings.json", f, "application/json")},
                    data={**common, "test": str(test_id),
                          "close_old_findings": "true"},
                )
                return result.get("finding_count", 0), test_id
            else:
                log.info(f"  import-scan (new test, engagement={engagement_id})")
                result = self._post(
                    "/import-scan/",
                    timeout=600,
                    files={"file": ("findings.json", f, "application/json")},
                    data={**common, "engagement": str(engagement_id),
                          "close_old_findings": "false"},
                )
                return result.get("finding_count", 0), result.get("test")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("=== Wazuh → DefectDojo enriched import starting ===")

    client = get_client()
    state  = load_state()

    log.info("Building agent cache from Wazuh API …")
    agent_cache = build_agent_cache()

    # Group findings by agent ID (stable across renames)
    grouped: dict[str, list] = defaultdict(list)
    total_docs = 0

    log.info("Scrolling vulnerability index …")
    for doc in iter_index(client, VULN_INDEX):
        total_docs += 1
        finding = build_finding(doc, agent_cache)
        if finding:
            agent_id = str(doc.get("agent", {}).get("id", "unknown")).strip()
            grouped[agent_id].append(finding)

    log.info(
        f"Fetched {total_docs} docs → "
        f"{sum(len(v) for v in grouped.values())} valid findings "
        f"across {len(grouped)} agents"
    )

    dd    = DefectDojoClient(DD_URL, DD_TOKEN)
    stats = {"imported": 0, "skipped": 0, "errors": 0}

    with tempfile.TemporaryDirectory() as tmpdir:
        for agent_id, findings in grouped.items():
            agent_info  = agent_cache.get(agent_id, {})
            agent_name  = agent_info.get("name") or agent_id
            agent_status = agent_info.get("status", "")

            # Skip disconnected agents that have no findings to avoid
            # closing valid findings from a temporarily offline machine
            if not agent_info:
                log.warning(f"Agent {agent_id} not found in Wazuh API — skipping")
                stats["skipped"] += 1
                continue

            if agent_status == "disconnected" and not findings:
                log.info(f"  '{agent_name}' disconnected with no findings — skipping")
                stats["skipped"] += 1
                continue

            log.info(f"Processing '{agent_name}' (id={agent_id}) — {len(findings)} findings")
            try:
                product_type  = agent_to_product_type(agent_id, agent_cache)
                type_id       = dd.get_product_type_id(product_type)
                agent_ip      = agent_info.get("ip") or ""
                product_id    = dd.get_or_create_product(agent_name, type_id, ip_str=agent_ip)
                engagement_id = dd.get_or_create_engagement(product_id)

                agent_state = state.get(agent_id, {})
                test_id     = agent_state.get("test_id") if isinstance(agent_state, dict) else agent_state

                # If no test ID in state, check DD for an existing test (e.g. after state reset)
                if not test_id:
                    test_id = dd.get_existing_test_id(engagement_id)
                    if test_id:
                        log.info(f"  Recovered existing test_id={test_id} from DefectDojo")

                # Handle agent rename — update product name in DD if it changed
                old_name = agent_state.get("name") if isinstance(agent_state, dict) else None
                if old_name and old_name != agent_name:
                    log.info(f"  Agent renamed: '{old_name}' → '{agent_name}' — updating product")
                    dd.rename_product(product_id, agent_name)

                count, new_test_id = dd.import_findings(
                    engagement_id, findings, tmpdir, test_id
                )

                state[agent_id] = {"test_id": new_test_id, "name": agent_name}
                save_state(state)

                log.info(f"  → {count} findings (test_id={new_test_id})")
                stats["imported"] += 1
            except Exception as exc:
                log.error(f"  Failed for '{agent_name}': {exc}")
                stats["errors"] += 1

    log.info(
        f"=== Done — agents={len(grouped)} "
        f"imported={stats['imported']} skipped={stats['skipped']} errors={stats['errors']} ==="
    )


if __name__ == "__main__":
    main()
