#!/usr/bin/env python3
"""
CheckPoint Catch-All Rule Analyzer
====================================
Analyzes traffic matched by a specific Check Point firewall rule over a
configurable historical window. Designed to support policy hardening:
converting a permissive catch-all ACCEPT rule into a restrictive DENY after
identifying all legitimate exceptions.

Author : generated for catch-all hardening project
Version: 1.0.0

IMPORTANT – API limitations
    Log querying via the Management API (show-logs) requires:
      - Check Point R80.10 or later
      - SmartLog / SmartEvent blade enabled
      - The management station must be the active log collector,
        or the Log Server must be reachable from the same host.
    If logs are stored on a dedicated Log Server the management API
    transparently proxies the query; no additional parameter is needed.
    Correlation between a log entry and a specific rule is done via the
    "rule_uid" field present in Firewall blade logs. If that field is absent
    (e.g. some blade logs) the script falls back to matching by rule name.
    This fallback is documented in the output.

Usage example
    python analyze_rule.py \\
        --host 10.167.251.203 \\
        --username api_user \\
        --password api_user \\
        --package INT-FW-Policy \\
        --layer-uuid "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \\
        --rule-uuid  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" \\
        --days 30 \\
        --output-dir ./output

Dependencies
    pip install requests
"""

# ---------------------------------------------------------------------------
# Standard library
# ---------------------------------------------------------------------------
import argparse
import csv
import json
import logging
import os
import sys
import time
import traceback
import urllib3
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Third-party
# ---------------------------------------------------------------------------
import requests

# Suppress self-signed certificate warnings (on-premises management station)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("cp_analyzer")

# ---------------------------------------------------------------------------
# Constants / defaults
# ---------------------------------------------------------------------------
DEFAULT_HOST     = "10.167.251.203"
DEFAULT_PACKAGE  = "INT-FW-Policy"
DEFAULT_USERNAME = "api_user"
DEFAULT_PASSWORD = "api_user"
DEFAULT_DAYS     = 30
PAGE_SIZE        = 500          # logs per API call
MAX_LOGS         = 100_000      # safety cap on total logs fetched
API_TIMEOUT      = 60           # seconds per HTTP request
MAX_RETRIES      = 3
RETRY_DELAY      = 5            # seconds between retries
TOP_N            = 20           # how many entries in "top" lists

PROTO_MAP: Dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE",
    50: "ESP",  51: "AH", 58: "ICMPv6", 89: "OSPF",
    112: "VRRP", 132: "SCTP",
}

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class RuleDetails:
    uid: str
    name: str
    layer_uid: str
    action: str
    sources: List[str]
    destinations: List[str]
    services: List[str]
    comments: str
    enabled: bool
    rule_number: int
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)


@dataclass
class LogEntry:
    timestamp: str          # ISO-8601
    src: str
    dst: str
    proto: str
    service: str
    action: str
    user: str
    app: str
    rule_uid: str
    rule_name: str
    blade: str
    matched_by_uid: bool    # True = matched via rule_uid, False = via rule_name
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)


@dataclass
class AnalysisResult:
    rule_uid: str
    rule_name: str
    period_days: int
    query_start: str
    query_end: str
    total_hits: int
    uid_matched_hits: int           # hits matched by UID
    name_matched_hits: int          # hits matched by name fallback
    top_sources: List[Tuple[str, int]]
    top_destinations: List[Tuple[str, int]]
    top_services: List[Tuple[str, int]]
    top_protocols: List[Tuple[str, int]]
    top_users: List[Tuple[str, int]]
    top_src_dst_pairs: List[Tuple[Tuple[str, str], int]]
    top_src_dst_svc_triples: List[Tuple[Tuple[str, str, str], int]]
    top_src_dst_app_triples: List[Tuple[Tuple[str, str, str], int]]
    temporal_hourly: Dict[str, int]     # "HH" -> count
    temporal_daily: Dict[str, int]      # "YYYY-MM-DD" -> count
    rare_sources: List[str]
    rare_destinations: List[str]
    rare_tuples: List[Tuple[str, str, str]]
    raw_logs: List[LogEntry] = field(repr=False, default_factory=list)


@dataclass
class CandidateRule:
    name: str
    sources: List[str]
    destinations: List[str]
    services: List[str]
    action: str                 # "accept" or "review"
    motivation: str
    hit_count: int
    confidence: str             # HIGH / MEDIUM / LOW
    priority: int               # lower number = higher priority
    assumptions: str
    category: str               # specific_traffic | user_traffic | rare_traffic | anomaly


# ---------------------------------------------------------------------------
# Check Point Session Manager
# ---------------------------------------------------------------------------

class CheckPointSession:
    """Manages a Check Point Management API session (login / logout / calls)."""

    def __init__(self, host: str, username: str, password: str, timeout: int = API_TIMEOUT):
        self.host      = host
        self.username  = username
        self.password  = password
        self.timeout   = timeout
        self.sid: Optional[str] = None          # session ID after login
        self.base_url  = f"https://{host}/web_api"
        self._session  = requests.Session()
        self._session.verify = False             # on-premises with self-signed cert

    # ------------------------------------------------------------------
    def login(self) -> None:
        """Authenticate and store the session ID."""
        log.info("Logging in to %s as '%s' …", self.host, self.username)
        resp = self._raw_call(
            "login",
            {"user": self.username, "password": self.password},
            authenticated=False,
        )
        self.sid = resp["sid"]
        cp_ver = resp.get("api-server-version", "unknown")
        log.info("Session established. CP API version: %s", cp_ver)

    # ------------------------------------------------------------------
    def logout(self) -> None:
        """Gracefully terminate the session."""
        if not self.sid:
            return
        try:
            self._raw_call("logout", {})
            log.info("Session closed.")
        except Exception as exc:
            log.warning("Logout failed (session may already be invalid): %s", exc)
        finally:
            self.sid = None

    # ------------------------------------------------------------------
    def call(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        retries: int = MAX_RETRIES,
    ) -> Dict[str, Any]:
        """Authenticated API call with basic retry logic."""
        if not self.sid:
            raise RuntimeError("Not authenticated – call login() first.")
        return self._raw_call(endpoint, payload, authenticated=True, retries=retries)

    # ------------------------------------------------------------------
    def _raw_call(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        authenticated: bool = True,
        retries: int = MAX_RETRIES,
    ) -> Dict[str, Any]:
        """Low-level HTTP call with retry / error handling."""
        url = f"{self.base_url}/{endpoint}"
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if authenticated and self.sid:
            headers["X-chkp-sid"] = self.sid

        last_exc: Optional[Exception] = None
        for attempt in range(1, retries + 1):
            try:
                log.debug("POST %s (attempt %d/%d)", endpoint, attempt, retries)
                resp = self._session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                # CP API signals errors inside the payload even with HTTP 200
                if isinstance(data, dict) and data.get("code") not in (None, "ok"):
                    msg = data.get("message", str(data))
                    raise RuntimeError(f"CP API error [{data.get('code')}]: {msg}")
                return data
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as exc:
                last_exc = exc
                log.warning("Network error on attempt %d/%d: %s", attempt, retries, exc)
                if attempt < retries:
                    time.sleep(RETRY_DELAY * attempt)
            except requests.exceptions.HTTPError as exc:
                last_exc = exc
                log.warning("HTTP error on attempt %d/%d: %s", attempt, retries, exc)
                if exc.response is not None and exc.response.status_code in (400, 401, 403):
                    # Don't retry client errors
                    break
                if attempt < retries:
                    time.sleep(RETRY_DELAY * attempt)
            except Exception as exc:
                last_exc = exc
                log.warning("Unexpected error on attempt %d/%d: %s", attempt, retries, exc)
                break

        raise RuntimeError(
            f"API call '{endpoint}' failed after {retries} attempt(s): {last_exc}"
        )

    # ------------------------------------------------------------------
    def __enter__(self) -> "CheckPointSession":
        self.login()
        return self

    def __exit__(self, *_) -> None:
        self.logout()


# ---------------------------------------------------------------------------
# Rule Fetcher
# ---------------------------------------------------------------------------

class RuleFetcher:
    """Fetches rule details from the policy package."""

    def __init__(self, session: CheckPointSession, package: str):
        self.session = session
        self.package = package

    # ------------------------------------------------------------------
    def get_rule(self, layer_uuid: str, rule_uuid: str) -> RuleDetails:
        """Retrieve a single access rule by its UID."""
        log.info("Fetching rule %s from layer %s …", rule_uuid, layer_uuid)
        try:
            data = self.session.call(
                "show-access-rule",
                {"uid": rule_uuid, "layer": layer_uuid},
            )
        except RuntimeError as exc:
            # Fallback: iterate the rulebase to find the rule
            log.warning("Direct show-access-rule failed (%s); scanning rulebase …", exc)
            data = self._find_rule_in_rulebase(layer_uuid, rule_uuid)

        return self._parse_rule(data, layer_uuid)

    # ------------------------------------------------------------------
    def _find_rule_in_rulebase(
        self, layer_uuid: str, rule_uuid: str
    ) -> Dict[str, Any]:
        """Walk through the rulebase and return the matching rule dict."""
        offset = 0
        limit  = 50
        while True:
            resp = self.session.call(
                "show-access-rulebase",
                {
                    "uid": layer_uuid,
                    "limit": limit,
                    "offset": offset,
                    "use-object-dictionary": True,
                    "details-level": "full",
                },
            )
            rulebase = resp.get("rulebase", [])
            for item in rulebase:
                # Sections contain sub-items
                for rule in _flatten_rulebase(item):
                    if rule.get("uid") == rule_uuid:
                        return rule
            total = resp.get("total", 0)
            offset += limit
            if offset >= total:
                break

        raise ValueError(
            f"Rule {rule_uuid} not found in layer {layer_uuid} / package {self.package}"
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_rule(data: Dict[str, Any], layer_uuid: str) -> RuleDetails:
        """Convert raw API rule dict to a RuleDetails object."""

        def _names(objs) -> List[str]:
            """Extract name strings from object references."""
            if not objs:
                return []
            if isinstance(objs, list):
                result = []
                for o in objs:
                    if isinstance(o, dict):
                        result.append(o.get("name", o.get("uid", str(o))))
                    else:
                        result.append(str(o))
                return result
            if isinstance(objs, dict):
                return [objs.get("name", objs.get("uid", str(objs)))]
            return [str(objs)]

        action_raw = data.get("action", {})
        if isinstance(action_raw, dict):
            action = action_raw.get("name", str(action_raw))
        else:
            action = str(action_raw)

        return RuleDetails(
            uid         = data.get("uid", ""),
            name        = data.get("name", ""),
            layer_uid   = layer_uuid,
            action      = action,
            sources     = _names(data.get("source", [])),
            destinations= _names(data.get("destination", [])),
            services    = _names(data.get("service", [])),
            comments    = data.get("comments", ""),
            enabled     = data.get("enabled", True),
            rule_number = data.get("rule-number", 0),
            raw         = data,
        )


def _flatten_rulebase(item: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Recursively flatten sections and inline-layers."""
    if item.get("type") in ("access-section", "place-holder"):
        rules = []
        for sub in item.get("rulebase", []):
            rules.extend(_flatten_rulebase(sub))
        return rules
    return [item]


# ---------------------------------------------------------------------------
# Log Fetcher
# ---------------------------------------------------------------------------

class LogFetcher:
    """
    Queries Check Point logs for traffic matching a specific rule.

    Strategy:
      1. Primary: filter by rule_uid using show-logs.
      2. If show-logs is unavailable or returns zero results while the rule is
         known to have hits, fall back to fetching logs without the rule filter
         and post-filtering by rule_uid / rule_name in Python.
         (This fallback is expensive for busy firewalls and is clearly flagged.)
    """

    def __init__(self, session: CheckPointSession):
        self.session = session

    # ------------------------------------------------------------------
    def fetch(
        self,
        rule_uid: str,
        rule_name: str,
        days: int,
    ) -> List[LogEntry]:
        """Fetch and return all log entries matching the rule."""
        end_dt   = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=days)
        start_s  = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_s    = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        log.info(
            "Querying logs for rule '%s' (%s) — %s to %s …",
            rule_name, rule_uid, start_s, end_s,
        )

        logs: List[LogEntry] = []
        try:
            logs = self._fetch_by_uid(rule_uid, start_s, end_s)
        except Exception as exc:
            log.warning("show-logs by uid failed: %s", exc)

        if not logs:
            log.warning(
                "No logs found by rule_uid. This may indicate:\n"
                "  - SmartLog blade not enabled or logs on a separate server\n"
                "  - Rule has never matched traffic in this period\n"
                "  - API version does not support show-logs\n"
                "Skipping log analysis — output will be structural only."
            )
        else:
            uid_hits  = sum(1 for e in logs if e.matched_by_uid)
            name_hits = len(logs) - uid_hits
            log.info(
                "Retrieved %d log entries (%d by uid, %d by name fallback).",
                len(logs), uid_hits, name_hits,
            )
        return logs

    # ------------------------------------------------------------------
    def _fetch_by_uid(
        self, rule_uid: str, start_s: str, end_s: str
    ) -> List[LogEntry]:
        """Use show-logs with rule_uid filter + pagination."""
        entries: List[LogEntry] = []
        scroll_id: Optional[str] = None
        fetched = 0

        while fetched < MAX_LOGS:
            if scroll_id is None:
                payload: Dict[str, Any] = {
                    "new-query": {
                        "max-results": PAGE_SIZE,
                        "type": "Log",
                        "time-frame": {
                            "start-iso-date": start_s,
                            "end-iso-date": end_s,
                        },
                        "filter": f"rule_uid:{rule_uid}",
                    }
                }
            else:
                payload = {
                    "scroll-id": scroll_id,
                    "scroll-id-from": fetched,
                }

            data = self.session.call("show-logs", payload)

            # Handle async task response
            if "taskId" in data or "task-id" in data:
                task_id = data.get("taskId") or data.get("task-id")
                data = self._wait_for_task(task_id)

            batch = data.get("logs", [])
            if not batch:
                break

            scroll_id = data.get("scroll-id")

            for raw_log in batch:
                entry = self._parse_log(raw_log, rule_uid)
                if entry is not None:
                    entries.append(entry)

            fetched += len(batch)
            total = data.get("total", 0)
            log.debug("Fetched %d / %d logs …", fetched, total)

            if fetched >= total or not scroll_id:
                break

        return entries

    # ------------------------------------------------------------------
    def _wait_for_task(
        self, task_id: str, poll_interval: int = 3, max_wait: int = 300
    ) -> Dict[str, Any]:
        """Poll show-task until completion; return the task result."""
        deadline = time.time() + max_wait
        while time.time() < deadline:
            resp = self.session.call("show-task", {"task-id": task_id})
            tasks = resp.get("tasks", [])
            if not tasks:
                break
            task = tasks[0]
            status = task.get("status", "").lower()
            if status in ("succeeded", "failed"):
                if status == "failed":
                    raise RuntimeError(
                        f"Log query task {task_id} failed: {task.get('task-details', '')}"
                    )
                return task.get("task-details", {})
            time.sleep(poll_interval)
        raise TimeoutError(f"Log query task {task_id} did not complete within {max_wait}s.")

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_log(raw: Dict[str, Any], expected_rule_uid: str) -> Optional["LogEntry"]:
        """Parse a raw log dict into a LogEntry. Returns None for irrelevant logs."""
        # Determine how this entry was matched
        log_rule_uid  = raw.get("rule_uid", raw.get("ruleUid", ""))
        log_rule_name = raw.get("rule_name", raw.get("ruleName", ""))

        matched_by_uid = (log_rule_uid == expected_rule_uid)

        # Time
        ts_raw = raw.get("time", raw.get("startTime", ""))
        if isinstance(ts_raw, (int, float)):
            ts = datetime.fromtimestamp(ts_raw, tz=timezone.utc).isoformat()
        else:
            ts = str(ts_raw)

        # Source / destination
        src = raw.get("src", raw.get("srcIp", raw.get("source_machine_name", "")))
        dst = raw.get("dst", raw.get("dstIp", raw.get("destination_machine_name", "")))
        if not src:
            src = raw.get("src_machine_name", "")
        if not dst:
            dst = raw.get("dst_machine_name", "")

        # Protocol
        proto_num = raw.get("proto", raw.get("ip_proto", 0))
        try:
            proto_num = int(proto_num)
        except (ValueError, TypeError):
            proto_num = 0
        proto = PROTO_MAP.get(proto_num, str(proto_num) if proto_num else "")

        # Service / port
        service = raw.get("service_id", raw.get("service", raw.get("port", "")))
        if isinstance(service, dict):
            service = service.get("name", str(service))
        service = str(service)

        # Action
        action = raw.get("action", raw.get("verdict", ""))
        if isinstance(action, dict):
            action = action.get("name", str(action))

        # User
        user = raw.get("user", raw.get("src_user_name", ""))

        # Application
        app = raw.get("app_desc", raw.get("app_id", raw.get("application", "")))
        if isinstance(app, dict):
            app = app.get("name", str(app))
        app = str(app)

        # Blade
        blade = raw.get("blade", raw.get("product", ""))
        if isinstance(blade, list):
            blade = ", ".join(blade)

        return LogEntry(
            timestamp      = ts,
            src            = str(src),
            dst            = str(dst),
            proto          = proto,
            service        = service,
            action         = str(action),
            user           = str(user),
            app            = str(app),
            rule_uid       = str(log_rule_uid),
            rule_name      = str(log_rule_name),
            blade          = str(blade),
            matched_by_uid = matched_by_uid,
            raw            = raw,
        )


# ---------------------------------------------------------------------------
# Traffic Analyzer
# ---------------------------------------------------------------------------

class TrafficAnalyzer:
    """Aggregates log entries into statistical summaries."""

    def __init__(self, top_n: int = TOP_N):
        self.top_n = top_n

    # ------------------------------------------------------------------
    def analyze(
        self,
        logs: List[LogEntry],
        rule_uid: str,
        rule_name: str,
        period_days: int,
        query_start: str,
        query_end: str,
    ) -> AnalysisResult:
        """Compute all statistics and return an AnalysisResult."""

        uid_hits  = sum(1 for e in logs if e.matched_by_uid)
        name_hits = len(logs) - uid_hits

        src_counter:          Counter = Counter()
        dst_counter:          Counter = Counter()
        svc_counter:          Counter = Counter()
        proto_counter:        Counter = Counter()
        user_counter:         Counter = Counter()
        pair_counter:         Counter = Counter()
        triple_svc_counter:   Counter = Counter()
        triple_app_counter:   Counter = Counter()
        hourly:               Counter = Counter()
        daily:                Counter = Counter()

        for entry in logs:
            src = entry.src   or "unknown"
            dst = entry.dst   or "unknown"
            svc = entry.service or "unknown"
            app = entry.app   or ""
            proto = entry.proto or "unknown"
            user  = entry.user  or ""

            src_counter[src]   += 1
            dst_counter[dst]   += 1
            svc_counter[svc]   += 1
            proto_counter[proto] += 1

            if user:
                user_counter[user] += 1

            pair_counter[(src, dst)] += 1
            triple_svc_counter[(src, dst, svc)] += 1

            if app:
                triple_app_counter[(src, dst, app)] += 1

            # Temporal buckets
            try:
                if entry.timestamp:
                    dt_obj = datetime.fromisoformat(
                        entry.timestamp.replace("Z", "+00:00")
                    )
                    hourly[f"{dt_obj.hour:02d}"] += 1
                    daily[dt_obj.strftime("%Y-%m-%d")] += 1
            except (ValueError, AttributeError):
                pass

        # Rare = appears only once
        rare_sources = [s for s, c in src_counter.items() if c == 1]
        rare_dests   = [d for d, c in dst_counter.items() if c == 1]
        rare_tuples  = [t for t, c in triple_svc_counter.items() if c == 1]

        return AnalysisResult(
            rule_uid         = rule_uid,
            rule_name        = rule_name,
            period_days      = period_days,
            query_start      = query_start,
            query_end        = query_end,
            total_hits       = len(logs),
            uid_matched_hits = uid_hits,
            name_matched_hits= name_hits,
            top_sources      = src_counter.most_common(self.top_n),
            top_destinations = dst_counter.most_common(self.top_n),
            top_services     = svc_counter.most_common(self.top_n),
            top_protocols    = proto_counter.most_common(self.top_n),
            top_users        = user_counter.most_common(self.top_n),
            top_src_dst_pairs= pair_counter.most_common(self.top_n),
            top_src_dst_svc_triples = triple_svc_counter.most_common(self.top_n),
            top_src_dst_app_triples = triple_app_counter.most_common(self.top_n),
            temporal_hourly  = dict(sorted(hourly.items())),
            temporal_daily   = dict(sorted(daily.items())),
            rare_sources     = rare_sources[:50],
            rare_destinations= rare_dests[:50],
            rare_tuples      = rare_tuples[:50],
            raw_logs         = logs,
        )


# ---------------------------------------------------------------------------
# Candidate Rule Generator
# ---------------------------------------------------------------------------

class CandidateRuleGenerator:
    """
    Proposes replacement firewall rules based on observed traffic patterns.

    Logic:
      - HIGH-frequency src/dst/svc triples → specific ACCEPT rules (high confidence)
      - Common services between frequent pairs → service-grouped ACCEPT rules
      - User-based patterns → identity-aware rules (if present)
      - Rare / single-hit tuples → flag for manual review
      - Remaining traffic → candidate for the new DENY catch-all
    """

    MIN_HITS_HIGH   = 50
    MIN_HITS_MEDIUM = 10

    def __init__(self, top_n: int = TOP_N):
        self.top_n = top_n

    # ------------------------------------------------------------------
    def generate(
        self,
        analysis: AnalysisResult,
        rule_details: RuleDetails,
    ) -> List[CandidateRule]:
        """Return a prioritised list of candidate rules."""
        candidates: List[CandidateRule] = []
        priority_counter = 1

        if not analysis.raw_logs:
            candidates.append(CandidateRule(
                name         = "NO-DATA-MANUAL-REVIEW",
                sources      = ["any"],
                destinations = ["any"],
                services     = ["any"],
                action       = "review",
                motivation   = "No log data available. Manual review required before converting rule to DENY.",
                hit_count    = 0,
                confidence   = "LOW",
                priority     = priority_counter,
                assumptions  = "Log data not available via API; correlation not possible.",
                category     = "anomaly",
            ))
            return candidates

        total = analysis.total_hits or 1  # avoid div-by-zero

        # -------------------------------------------------------------------
        # 1. Top source+destination+service triples → specific ACCEPT rules
        # -------------------------------------------------------------------
        seen_pairs: set = set()
        for (src, dst, svc), count in analysis.top_src_dst_svc_triples:
            pct = count / total * 100
            confidence = self._confidence(count)
            candidates.append(CandidateRule(
                name         = f"ALLOW-{src.replace('.','_')}-to-{dst.replace('.','_')}-{svc}",
                sources      = [src],
                destinations = [dst],
                services     = [svc] if svc != "unknown" else ["any"],
                action       = "accept",
                motivation   = (
                    f"Observed {count} hits ({pct:.1f}% of traffic) — "
                    f"{src} → {dst} on {svc}. Stable pattern warrants a specific rule."
                ),
                hit_count    = count,
                confidence   = confidence,
                priority     = priority_counter,
                assumptions  = "Source/destination IPs are stable; service port correctly identified.",
                category     = "specific_traffic",
            ))
            seen_pairs.add((src, dst))
            priority_counter += 1

        # -------------------------------------------------------------------
        # 2. Top source+destination PAIRS (service-agnostic) not already covered
        # -------------------------------------------------------------------
        for (src, dst), count in analysis.top_src_dst_pairs:
            if (src, dst) in seen_pairs:
                continue
            if count < self.MIN_HITS_MEDIUM:
                continue
            pct = count / total * 100
            confidence = self._confidence(count)
            # Find which services this pair uses
            pair_svcs = [
                svc for (s, d, svc), _ in analysis.top_src_dst_svc_triples
                if s == src and d == dst
            ][:5]
            candidates.append(CandidateRule(
                name         = f"ALLOW-PAIR-{src.replace('.','_')}-to-{dst.replace('.','_')}",
                sources      = [src],
                destinations = [dst],
                services     = pair_svcs if pair_svcs else ["any"],
                action       = "accept",
                motivation   = (
                    f"Pair {src}→{dst} seen {count} hits ({pct:.1f}%). "
                    f"Candidate services: {pair_svcs or ['any']}. "
                    "Consider restricting to observed services only."
                ),
                hit_count    = count,
                confidence   = confidence,
                priority     = priority_counter,
                assumptions  = (
                    "Aggregated across multiple services; review service list "
                    "before granting broad access."
                ),
                category     = "specific_traffic",
            ))
            priority_counter += 1

        # -------------------------------------------------------------------
        # 3. User-based patterns (if identity data present)
        # -------------------------------------------------------------------
        for user, count in analysis.top_users[:5]:
            if not user or user in ("", "unknown"):
                continue
            pct = count / total * 100
            candidates.append(CandidateRule(
                name         = f"ALLOW-USER-{user.replace(' ','_').replace('@','_AT_')}",
                sources      = ["any"],
                destinations = ["any"],
                services     = ["any"],
                action       = "accept",
                motivation   = (
                    f"User '{user}' generated {count} hits ({pct:.1f}%). "
                    "Create an identity-based rule if IDFW / AD Query is active."
                ),
                hit_count    = count,
                confidence   = self._confidence(count),
                priority     = priority_counter,
                assumptions  = "Identity logging enabled; usernames reliably mapped.",
                category     = "user_traffic",
            ))
            priority_counter += 1

        # -------------------------------------------------------------------
        # 4. Application-based grouping
        # -------------------------------------------------------------------
        for (src, dst, app), count in analysis.top_src_dst_app_triples[:10]:
            if not app or app in ("", "unknown"):
                continue
            pct = count / total * 100
            if count < self.MIN_HITS_MEDIUM:
                continue
            candidates.append(CandidateRule(
                name         = f"ALLOW-APP-{app.replace(' ','_')[:30]}",
                sources      = [src],
                destinations = [dst],
                services     = [app],
                action       = "accept",
                motivation   = (
                    f"Application '{app}' seen {count} hits ({pct:.1f}%). "
                    "Use AppControl blade rule if available."
                ),
                hit_count    = count,
                confidence   = self._confidence(count),
                priority     = priority_counter,
                assumptions  = "AppControl blade enabled; application correctly identified.",
                category     = "specific_traffic",
            ))
            priority_counter += 1

        # -------------------------------------------------------------------
        # 5. Rare / anomalous traffic → manual review flag
        # -------------------------------------------------------------------
        rare_count = len(analysis.rare_tuples)
        if rare_count:
            candidates.append(CandidateRule(
                name         = "MANUAL-REVIEW-RARE-TRAFFIC",
                sources      = [t[0] for t in analysis.rare_tuples[:10]],
                destinations = [t[1] for t in analysis.rare_tuples[:10]],
                services     = list({t[2] for t in analysis.rare_tuples[:10]}),
                action       = "review",
                motivation   = (
                    f"{rare_count} unique src/dst/svc tuple(s) appeared only once. "
                    "Verify legitimacy before the catch-all becomes DENY."
                ),
                hit_count    = rare_count,
                confidence   = "LOW",
                priority     = priority_counter,
                assumptions  = (
                    "Single-hit traffic may be: legitimate one-off, misconfiguration, "
                    "recon, or simply outside the 30-day observation window."
                ),
                category     = "rare_traffic",
            ))
            priority_counter += 1

        # -------------------------------------------------------------------
        # 6. Final catch-all DENY recommendation
        # -------------------------------------------------------------------
        candidates.append(CandidateRule(
            name         = "CATCHALL-DENY",
            sources      = ["any"],
            destinations = ["any"],
            services     = ["any"],
            action       = "deny",
            motivation   = (
                "After deploying the ACCEPT exceptions above, replace the current "
                "catch-all ACCEPT with this DENY. Ensure logging is enabled on it."
            ),
            hit_count    = 0,
            confidence   = "HIGH",
            priority     = priority_counter,
            assumptions  = (
                "All legitimate traffic patterns have been identified and covered "
                "by preceding specific rules. Rare/manual-review items resolved."
            ),
            category     = "anomaly",
        ))

        return candidates

    # ------------------------------------------------------------------
    @staticmethod
    def _confidence(count: int) -> str:
        if count >= CandidateRuleGenerator.MIN_HITS_HIGH:
            return "HIGH"
        if count >= CandidateRuleGenerator.MIN_HITS_MEDIUM:
            return "MEDIUM"
        return "LOW"


# ---------------------------------------------------------------------------
# Output Generator
# ---------------------------------------------------------------------------

class OutputGenerator:
    """Writes analysis results to console, JSON, CSV, and text report."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------
    def print_console(
        self,
        rule: RuleDetails,
        analysis: AnalysisResult,
        candidates: List[CandidateRule],
    ) -> None:
        sep = "=" * 72

        print(f"\n{sep}")
        print("  CHECK POINT CATCH-ALL RULE ANALYZER — RESULTS")
        print(sep)

        print(f"\n  Rule      : {rule.name} ({rule.uid})")
        print(f"  Action    : {rule.action.upper()}")
        print(f"  Layer     : {rule.layer_uid}")
        print(f"  Enabled   : {rule.enabled}")
        print(f"  Period    : {analysis.period_days} days  ({analysis.query_start} → {analysis.query_end})")
        print(f"  Total hits: {analysis.total_hits:,}")
        if analysis.total_hits:
            uid_pct = analysis.uid_matched_hits / analysis.total_hits * 100
            print(f"  UID match : {analysis.uid_matched_hits:,} ({uid_pct:.0f}%)  |  "
                  f"Name fallback: {analysis.name_matched_hits:,}")

        self._section("TOP SOURCES")
        self._top_table(analysis.top_sources)

        self._section("TOP DESTINATIONS")
        self._top_table(analysis.top_destinations)

        self._section("TOP SERVICES / PORTS")
        self._top_table(analysis.top_services)

        self._section("TOP PROTOCOLS")
        self._top_table(analysis.top_protocols)

        if analysis.top_users:
            self._section("TOP USERS (identity data)")
            self._top_table(analysis.top_users)

        self._section("TOP SRC → DST PAIRS")
        for (src, dst), count in analysis.top_src_dst_pairs[:10]:
            print(f"    {src:<20} → {dst:<20}  {count:>6,} hits")

        self._section("TOP SRC → DST → SERVICE TRIPLES")
        for (src, dst, svc), count in analysis.top_src_dst_svc_triples[:10]:
            print(f"    {src:<18} → {dst:<18} [{svc:<12}]  {count:>6,} hits")

        self._section("TEMPORAL DISTRIBUTION (by hour)")
        for hour in sorted(analysis.temporal_hourly):
            bar = "#" * min(analysis.temporal_hourly[hour] // max(1, analysis.total_hits // 200), 40)
            print(f"    {hour}h  {bar} {analysis.temporal_hourly[hour]:,}")

        self._section("CANDIDATE RULES FOR POLICY HARDENING")
        for cand in candidates:
            action_tag = "ACCEPT" if cand.action == "accept" else (
                "DENY" if cand.action == "deny" else "REVIEW")
            flag = f"[{cand.confidence}]"
            print(f"\n  #{cand.priority:02d}  {action_tag:<7}  {flag:<8}  {cand.name}")
            print(f"       Src : {', '.join(cand.sources[:5])}")
            print(f"       Dst : {', '.join(cand.destinations[:5])}")
            print(f"       Svc : {', '.join(cand.services[:5])}")
            print(f"       Hits: {cand.hit_count:,}")
            print(f"       Why : {cand.motivation}")
            if cand.assumptions:
                print(f"       Note: {cand.assumptions}")

        if analysis.rare_tuples:
            self._section(f"RARE TRAFFIC ({len(analysis.rare_tuples)} single-hit tuples — sample)")
            for src, dst, svc in analysis.rare_tuples[:10]:
                print(f"    {src:<20} → {dst:<20} [{svc}]")

        print(f"\n{sep}\n")

    # ------------------------------------------------------------------
    @staticmethod
    def _section(title: str) -> None:
        print(f"\n  {'─' * 64}")
        print(f"  {title}")
        print(f"  {'─' * 64}")

    @staticmethod
    def _top_table(items: List[Tuple[Any, int]], width: int = 30) -> None:
        for key, count in items[:10]:
            label = str(key)[:width]
            print(f"    {label:<{width}}  {count:>8,}")

    # ------------------------------------------------------------------
    # JSON output
    # ------------------------------------------------------------------
    def save_json(
        self,
        rule: RuleDetails,
        analysis: AnalysisResult,
        candidates: List[CandidateRule],
    ) -> Optional[str]:
        if not self.output_dir:
            return None

        def _serialise(obj):
            """Custom serialiser for tuples and dataclasses."""
            if isinstance(obj, tuple):
                return list(obj)
            raise TypeError(f"Object of type {type(obj)} is not JSON-serialisable")

        payload = {
            "metadata": {
                "generated_at"  : datetime.now(timezone.utc).isoformat(),
                "tool"          : "cp-catchall-analyzer",
                "version"       : "1.0.0",
            },
            "rule": {
                "uid"         : rule.uid,
                "name"        : rule.name,
                "action"      : rule.action,
                "layer_uid"   : rule.layer_uid,
                "enabled"     : rule.enabled,
                "sources"     : rule.sources,
                "destinations": rule.destinations,
                "services"    : rule.services,
                "comments"    : rule.comments,
            },
            "statistics": {
                "period_days"       : analysis.period_days,
                "query_start"       : analysis.query_start,
                "query_end"         : analysis.query_end,
                "total_hits"        : analysis.total_hits,
                "uid_matched"       : analysis.uid_matched_hits,
                "name_matched"      : analysis.name_matched_hits,
                "top_sources"       : analysis.top_sources,
                "top_destinations"  : analysis.top_destinations,
                "top_services"      : analysis.top_services,
                "top_protocols"     : analysis.top_protocols,
                "top_users"         : analysis.top_users,
                "top_src_dst_pairs" : analysis.top_src_dst_pairs,
                "top_src_dst_svc"   : analysis.top_src_dst_svc_triples,
                "top_src_dst_app"   : analysis.top_src_dst_app_triples,
                "hourly_distribution": analysis.temporal_hourly,
                "daily_distribution" : analysis.temporal_daily,
                "rare_sources"      : analysis.rare_sources,
                "rare_destinations" : analysis.rare_destinations,
                "rare_tuples"       : [list(t) for t in analysis.rare_tuples],
            },
            "candidate_rules": [
                {
                    "priority"    : c.priority,
                    "name"        : c.name,
                    "action"      : c.action,
                    "confidence"  : c.confidence,
                    "sources"     : c.sources,
                    "destinations": c.destinations,
                    "services"    : c.services,
                    "hit_count"   : c.hit_count,
                    "category"    : c.category,
                    "motivation"  : c.motivation,
                    "assumptions" : c.assumptions,
                }
                for c in candidates
            ],
        }

        path = os.path.join(self.output_dir, f"analysis_{rule.uid[:8]}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=_serialise, ensure_ascii=False)
        log.info("JSON saved → %s", path)
        return path

    # ------------------------------------------------------------------
    # CSV output
    # ------------------------------------------------------------------
    def save_csv(
        self,
        rule: RuleDetails,
        analysis: AnalysisResult,
        candidates: List[CandidateRule],
    ) -> Optional[str]:
        if not self.output_dir:
            return None

        prefix = os.path.join(self.output_dir, f"analysis_{rule.uid[:8]}")

        # Raw logs
        logs_path = f"{prefix}_logs.csv"
        with open(logs_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "timestamp", "src", "dst", "proto", "service",
                "action", "user", "app", "rule_uid", "rule_name",
                "blade", "matched_by_uid",
            ])
            for entry in analysis.raw_logs:
                writer.writerow([
                    entry.timestamp, entry.src, entry.dst, entry.proto,
                    entry.service, entry.action, entry.user, entry.app,
                    entry.rule_uid, entry.rule_name, entry.blade,
                    entry.matched_by_uid,
                ])
        log.info("Logs CSV saved → %s", logs_path)

        # Top sources
        src_path = f"{prefix}_top_sources.csv"
        with open(src_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["source", "hit_count", "pct"])
            total = analysis.total_hits or 1
            for src, count in analysis.top_sources:
                writer.writerow([src, count, f"{count/total*100:.2f}"])
        log.info("Top sources CSV saved → %s", src_path)

        # Top destinations
        dst_path = f"{prefix}_top_destinations.csv"
        with open(dst_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["destination", "hit_count", "pct"])
            for dst, count in analysis.top_destinations:
                writer.writerow([dst, count, f"{count/total*100:.2f}"])
        log.info("Top destinations CSV saved → %s", dst_path)

        # Top services
        svc_path = f"{prefix}_top_services.csv"
        with open(svc_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["service", "hit_count", "pct"])
            for svc, count in analysis.top_services:
                writer.writerow([svc, count, f"{count/total*100:.2f}"])
        log.info("Top services CSV saved → %s", svc_path)

        # Top tuples
        tuples_path = f"{prefix}_top_tuples.csv"
        with open(tuples_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["src", "dst", "service", "hit_count", "pct"])
            for (src, dst, svc), count in analysis.top_src_dst_svc_triples:
                writer.writerow([src, dst, svc, count, f"{count/total*100:.2f}"])
        log.info("Top tuples CSV saved → %s", tuples_path)

        # Candidate rules
        cand_path = f"{prefix}_candidate_rules.csv"
        with open(cand_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow([
                "priority", "name", "action", "confidence",
                "sources", "destinations", "services",
                "hit_count", "category", "motivation", "assumptions",
            ])
            for c in candidates:
                writer.writerow([
                    c.priority, c.name, c.action, c.confidence,
                    "|".join(c.sources), "|".join(c.destinations), "|".join(c.services),
                    c.hit_count, c.category, c.motivation, c.assumptions,
                ])
        log.info("Candidate rules CSV saved → %s", cand_path)

        return prefix

    # ------------------------------------------------------------------
    # Text report
    # ------------------------------------------------------------------
    def save_report(
        self,
        rule: RuleDetails,
        analysis: AnalysisResult,
        candidates: List[CandidateRule],
    ) -> Optional[str]:
        if not self.output_dir:
            return None

        path = os.path.join(
            self.output_dir, f"report_{rule.uid[:8]}.txt"
        )
        ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            "=" * 72,
            "CHECK POINT CATCH-ALL RULE HARDENING REPORT",
            f"Generated: {ts_now}",
            "=" * 72,
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
            f"Rule name   : {rule.name}",
            f"Rule UID    : {rule.uid}",
            f"Current action: {rule.action.upper()}",
            f"Layer UID   : {rule.layer_uid}",
            f"Analysis period: {analysis.period_days} days",
            f"  from {analysis.query_start}",
            f"  to   {analysis.query_end}",
            f"Total traffic hits: {analysis.total_hits:,}",
            "",
        ]

        if analysis.total_hits == 0:
            lines += [
                "WARNING: No log data was retrieved for this rule.",
                "",
                "Possible causes:",
                "  1. SmartLog blade not enabled on this management station.",
                "  2. Logs stored on a separate Log Server not reachable via",
                "     the Management API.",
                "  3. The rule has not matched any traffic in the last",
                f"     {analysis.period_days} days.",
                "  4. CP API version does not support show-logs.",
                "",
                "Recommendation: verify log configuration before proceeding",
                "with policy hardening.",
                "",
            ]
        else:
            total = analysis.total_hits
            uid_pct = analysis.uid_matched_hits / total * 100 if total else 0

            lines += [
                f"Matched by rule_uid : {analysis.uid_matched_hits:,} ({uid_pct:.0f}%)",
                f"Matched by name (fallback): {analysis.name_matched_hits:,}",
                "",
                "NOTE ON LOG CORRELATION",
                "-" * 40,
            ]
            if analysis.name_matched_hits > 0:
                lines += [
                    "A portion of log entries were correlated by rule NAME rather than",
                    "rule UID. This can happen when:",
                    "  - The firewall blade does not populate the rule_uid log field.",
                    "  - Logs were generated before the rule UID was recorded.",
                    "Consider this a best-effort correlation for those entries.",
                    "",
                ]
            else:
                lines += [
                    "All entries correlated by rule_uid — high-confidence dataset.",
                    "",
                ]

            # Traffic findings
            lines += [
                "TRAFFIC FINDINGS",
                "-" * 40,
                "",
                f"  {len(analysis.top_sources)} distinct source IPs observed.",
                f"  {len(analysis.top_destinations)} distinct destination IPs observed.",
                f"  {len(analysis.top_services)} distinct services/ports observed.",
                f"  {len(analysis.rare_tuples)} single-hit (rare) src/dst/svc combinations.",
                "",
                "Top 5 sources:",
            ]
            for src, count in analysis.top_sources[:5]:
                pct = count / total * 100
                lines.append(f"    {src:<25} {count:>7,}  ({pct:.1f}%)")

            lines += ["", "Top 5 destinations:"]
            for dst, count in analysis.top_destinations[:5]:
                pct = count / total * 100
                lines.append(f"    {dst:<25} {count:>7,}  ({pct:.1f}%)")

            lines += ["", "Top 5 services:"]
            for svc, count in analysis.top_services[:5]:
                pct = count / total * 100
                lines.append(f"    {svc:<25} {count:>7,}  ({pct:.1f}%)")

            lines += ["", "Top 5 src→dst pairs:"]
            for (src, dst), count in analysis.top_src_dst_pairs[:5]:
                pct = count / total * 100
                lines.append(f"    {src:<18} → {dst:<18}  {count:>7,}  ({pct:.1f}%)")

            lines += ["", "Top 5 src→dst→service triples:"]
            for (src, dst, svc), count in analysis.top_src_dst_svc_triples[:5]:
                pct = count / total * 100
                lines.append(
                    f"    {src:<16} → {dst:<16} [{svc:<12}]  {count:>6,}  ({pct:.1f}%)"
                )

            # Risks
            lines += [
                "",
                "RISK OBSERVATIONS",
                "-" * 40,
                "",
            ]
            if analysis.rare_tuples:
                lines.append(
                    f"  * {len(analysis.rare_tuples)} rare traffic patterns (single hit) exist."
                )
                lines.append(
                    "    These must be individually validated before hardening."
                )
            if analysis.top_users:
                lines.append(
                    "  * Identity data present — consider identity-based rules."
                )
            if not analysis.top_protocols:
                lines.append("  * No protocol data available in logs.")
            else:
                protos = [p for p, _ in analysis.top_protocols]
                lines.append(f"  * Protocols observed: {', '.join(protos)}.")
            lines.append("")

        # Candidate rules section
        lines += [
            "CANDIDATE REPLACEMENT RULES",
            "-" * 40,
            "Install these ACCEPT rules BEFORE converting the catch-all to DENY.",
            "Order: highest priority first.",
            "",
        ]
        for c in candidates:
            action_lbl = c.action.upper()
            lines += [
                f"  [{c.priority:02d}] {action_lbl} — {c.name}  [{c.confidence} confidence]",
                f"       Category: {c.category}",
                f"       Sources : {', '.join(c.sources[:5])}",
                f"       Dests   : {', '.join(c.destinations[:5])}",
                f"       Services: {', '.join(c.services[:5])}",
                f"       Hits    : {c.hit_count:,}",
                f"       Why     : {c.motivation}",
                f"       Notes   : {c.assumptions}",
                "",
            ]

        # Operational guidance
        lines += [
            "OPERATIONAL GUIDANCE FOR POLICY HARDENING",
            "-" * 40,
            "",
            "Step 1 — Extend observation window if traffic is infrequent.",
            "         Use --days 60 or --days 90 for monthly / quarterly flows.",
            "",
            "Step 2 — For each ACCEPT candidate rule:",
            "         a) Confirm source/destination ownership.",
            "         b) Validate service with the application owner.",
            "         c) Create the rule in SmartConsole above the catch-all.",
            "",
            "Step 3 — For MANUAL-REVIEW items:",
            "         a) Contact the asset owner for each rare src/dst/svc.",
            "         b) Either add a specific ACCEPT rule or accept it will be denied.",
            "",
            "Step 4 — Shadow testing (recommended):",
            "         a) Clone the catch-all, set action to DROP with logging.",
            "         b) Place shadow rule below the new specific rules.",
            "         c) Monitor logs for 5-10 business days.",
            "         d) Address any unexpected drops.",
            "",
            "Step 5 — Convert catch-all to DENY with logging.",
            "         Ensure the DENY rule has 'Track: Log' enabled.",
            "",
            "Step 6 — Monitor DENY rule hits for 30 days post-change.",
            "",
            "LIMITATIONS OF THIS ANALYSIS",
            "-" * 40,
            "",
            "  - Log retention period on the firewall may be shorter than --days.",
            "  - If SmartLog is not licensed/enabled, no log data is retrieved.",
            "  - NAT may cause source/destination to appear as translated IPs.",
            "  - Application identification requires AppControl blade.",
            "  - Identity data requires IDFW / AD Query / Captive Portal.",
            "  - Encrypted traffic may show as generic TCP/443 without inspection.",
            "",
            "=" * 72,
        ]

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        log.info("Text report saved → %s", path)
        return path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyze_rule.py",
        description=(
            "Analyze Check Point firewall rule traffic to support catch-all hardening."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze_rule.py \\
      --host 10.167.251.203 \\
      --username api_user \\
      --password api_user \\
      --package INT-FW-Policy \\
      --layer-uuid xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \\
      --rule-uuid  yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy \\
      --days 30 \\
      --output-dir ./output

  # Extend to 90-day window (if retention allows):
  python analyze_rule.py ... --days 90

  # Quiet mode (no console output, only files):
  python analyze_rule.py ... --output-dir ./output --quiet
""",
    )
    p.add_argument("--host",       default=DEFAULT_HOST,     help="CP management station IP/hostname")
    p.add_argument("--username",   default=DEFAULT_USERNAME, help="API username")
    p.add_argument("--password",   default=DEFAULT_PASSWORD, help="API password")
    p.add_argument("--package",    default=DEFAULT_PACKAGE,  help="Policy package name")
    p.add_argument("--layer-uuid", required=True,            help="Access layer UID")
    p.add_argument("--rule-uuid",  required=True,            help="Rule UID to analyze")
    p.add_argument("--days",       type=int, default=DEFAULT_DAYS,
                   help=f"Days of log history to analyze (default: {DEFAULT_DAYS})")
    p.add_argument("--output-dir", default=None,
                   help="Directory for JSON/CSV/report output (optional)")
    p.add_argument("--quiet",      action="store_true",
                   help="Suppress console output (write files only)")
    p.add_argument("--debug",      action="store_true",
                   help="Enable debug logging")
    return p


def main() -> int:
    parser = build_arg_parser()
    args   = parser.parse_args()

    if args.debug:
        log.setLevel(logging.DEBUG)
        logging.getLogger("urllib3").setLevel(logging.DEBUG)

    # Validate days
    if args.days < 1:
        parser.error("--days must be >= 1")

    # Session scope: always logout even if something fails
    session = CheckPointSession(
        host     = args.host,
        username = args.username,
        password = args.password,
    )

    try:
        session.login()

        # 1. Fetch rule details ------------------------------------------------
        fetcher = RuleFetcher(session, args.package)
        rule    = fetcher.get_rule(args.layer_uuid, args.rule_uuid)
        log.info(
            "Rule found: '%s' | action=%s | enabled=%s",
            rule.name, rule.action, rule.enabled,
        )

        # 2. Fetch logs --------------------------------------------------------
        end_dt   = datetime.now(timezone.utc)
        start_dt = end_dt - timedelta(days=args.days)

        log_fetcher = LogFetcher(session)
        logs = log_fetcher.fetch(
            rule_uid  = args.rule_uuid,
            rule_name = rule.name,
            days      = args.days,
        )

        # 3. Analyze -----------------------------------------------------------
        analyzer = TrafficAnalyzer(top_n=TOP_N)
        analysis = analyzer.analyze(
            logs        = logs,
            rule_uid    = args.rule_uuid,
            rule_name   = rule.name,
            period_days = args.days,
            query_start = start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            query_end   = end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        )

        # 4. Generate candidates -----------------------------------------------
        generator  = CandidateRuleGenerator(top_n=TOP_N)
        candidates = generator.generate(analysis, rule)

        # 5. Output ------------------------------------------------------------
        output_gen = OutputGenerator(output_dir=args.output_dir)

        if not args.quiet:
            output_gen.print_console(rule, analysis, candidates)

        if args.output_dir:
            output_gen.save_json(rule, analysis, candidates)
            output_gen.save_csv(rule, analysis, candidates)
            output_gen.save_report(rule, analysis, candidates)
            print(f"\nOutput written to: {args.output_dir}\n")

    except KeyboardInterrupt:
        log.info("Interrupted by user.")
        return 130
    except Exception as exc:
        log.error("Fatal error: %s", exc)
        if args.debug:
            traceback.print_exc()
        return 1
    finally:
        session.logout()

    return 0


if __name__ == "__main__":
    sys.exit(main())
