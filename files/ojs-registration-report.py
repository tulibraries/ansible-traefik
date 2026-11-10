#!/usr/bin/env python3
"""Build a review-oriented report from Traefik JSON access logs.

The report deliberately describes registrations, activations, and logins as
observed requests.  A reverse proxy access log cannot prove that an account
was created, an email was confirmed, or a login succeeded.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import gzip
import glob
import ipaddress
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlsplit
from zoneinfo import ZoneInfo


UTC = dt.timezone.utc
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
ASSET_SUFFIXES = (
    ".css",
    ".eot",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".png",
    ".svg",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
)
GLOBAL_JOURNAL_ROUTES = {
    "api",
    "catalog",
    "index",
    "login",
    "register",
    "search",
    "user",
}
MALFORMED_MARKERS = (
    "..",
    "\\",
    "%00",
    "%2e%2e",
    "/.env",
    "/.git",
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
)
REPORT_FILENAME = re.compile(r"^report-(\d{4}-\d{2}-\d{2})\.md$")


def first_value(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return None


def parse_time(value: Any) -> Optional[dt.datetime]:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def parse_status(value: Any) -> Optional[int]:
    try:
        status = int(value)
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 999 else None


def client_ip(value: Any) -> str:
    text = str(value or "").strip()
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            text = host
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return text or "unknown"


def host_without_port(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")]
    if text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            return host
    return text


def path_parts(raw_path: Any) -> tuple[str, str, str]:
    raw = str(raw_path or "/")
    split = urlsplit(raw)
    path = unquote(split.path or "/")
    lower = path.lower()
    return raw, path, lower


def journal_for(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    if parts and parts[0].lower() == "index.php":
        parts = parts[1:]
    if not parts:
        return "(site-wide)"
    candidate = parts[0]
    if candidate.lower() in GLOBAL_JOURNAL_ROUTES:
        return "(site-wide)"
    return candidate


def is_asset(path: str) -> bool:
    lower = path.lower().split("?", 1)[0]
    return lower.endswith(ASSET_SUFFIXES) or lower in {"/favicon.ico", "/robots.txt"}


def is_malformed(raw_path: str, decoded_path: str) -> bool:
    lower = raw_path.lower()
    return any(marker in lower or marker in decoded_path.lower() for marker in MALFORMED_MARKERS)


def activation_username(raw_path: str) -> Optional[str]:
    query = parse_qs(urlsplit(raw_path).query, keep_blank_values=False)
    for key in ("username", "user", "userName"):
        values = query.get(key)
        if values and values[0]:
            return unquote(values[0])[:160]
    return None


def configured_site(host: str, sites: list[dict[str, Any]]) -> Optional[str]:
    for site in sites:
        hosts = {host_without_port(item) for item in site.get("hosts", [])}
        if host in hosts:
            return str(site.get("name") or host)
    return None


def classify(method: str, lower_path: str, status: Optional[int], raw_path: str) -> str:
    register = re.search(r"/(?:index\.php/[^/]+/)?user/register(?:/|$)", lower_path)
    login = re.search(r"/(?:index\.php/[^/]+/)?user/login(?:/|$)", lower_path)
    activation = re.search(r"/(?:index\.php/[^/]+/)?user/activate(?:/|$)", lower_path)
    submission = "submission" in lower_path or "submissions" in lower_path
    upload = bool(re.search(r"(?:upload|fileupload|attachment|/files(?:/|$)|/file(?:/|$))", lower_path))

    if method == "POST" and register:
        return "registration attempt"
    if activation:
        return "activation observed activity"
    if login:
        return "login observed activity"
    if upload and method in WRITE_METHODS:
        return "upload attempt"
    if upload:
        return "upload page or asset"
    if submission and method in WRITE_METHODS:
        return "submission change request"
    if submission:
        return "submission page visit"
    if is_malformed(raw_path, lower_path):
        return "malformed path"
    if status is not None and status >= 400:
        return "error response"
    return "other request"


def event_from_record(record: dict[str, Any], sites: list[dict[str, Any]]) -> Optional[dict[str, Any]]:
    timestamp = parse_time(first_value(record, "StartUTC", "StartLocal", "time", "Time", "timestamp"))
    if timestamp is None:
        return None
    host = host_without_port(first_value(record, "RequestHost", "requestHost", "Host", "host"))
    site = configured_site(host, sites)
    if site is None:
        return None
    method = str(first_value(record, "RequestMethod", "requestMethod", "Method", "method") or "GET").upper()
    raw_path, path, lower_path = path_parts(first_value(record, "RequestURI", "requestURI", "RequestURL", "requestURL", "RequestPath", "requestPath", "Path", "path"))
    status = parse_status(first_value(record, "DownstreamStatus", "downstreamStatus", "OriginStatus", "originStatus", "status"))
    username = activation_username(raw_path) if "user/activate" in lower_path else None
    if "user/activate" in lower_path and not username:
        username = "(not present in access log)"
    return {
        "time": timestamp,
        "ip": client_ip(first_value(record, "ClientAddr", "clientAddr", "ClientHost", "clientHost")),
        "host": host or "(unknown host)",
        "site": site,
        "journal": journal_for(path),
        "method": method,
        "path": path,
        "raw_path": raw_path,
        "status": status,
        "kind": classify(method, lower_path, status, raw_path),
        "username": username,
    }


def read_logs(globs: list[str], sites: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    events: list[dict[str, Any]] = []
    matched: set[str] = set()
    files: list[dict[str, Any]] = []
    unreadable: list[dict[str, str]] = []
    invalid_lines = 0
    no_timestamp = 0
    for pattern in globs:
        matched.update(glob.glob(pattern))
    for filename in sorted(matched):
        stat: dict[str, Any] = {"file": filename, "lines": 0, "events": 0, "first": None, "last": None}
        try:
            opener = gzip.open if filename.endswith(".gz") else open
            with opener(filename, "rt", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    stat["lines"] += 1
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        invalid_lines += 1
                        continue
                    timestamp = parse_time(first_value(record, "StartUTC", "StartLocal", "time", "Time", "timestamp"))
                    if timestamp is None:
                        no_timestamp += 1
                        continue
                    stat["first"] = min(stat["first"], timestamp) if stat["first"] else timestamp
                    stat["last"] = max(stat["last"], timestamp) if stat["last"] else timestamp
                    event = event_from_record(record, sites)
                    if event is not None:
                        stat["events"] += 1
                        events.append(event)
        except (OSError, UnicodeError) as exc:
            unreadable.append({"file": filename, "error": str(exc)})
        files.append(stat)
    return events, {
        "patterns": globs,
        "matched": sorted(matched),
        "files": files,
        "unreadable": unreadable,
        "invalid_lines": invalid_lines,
        "no_timestamp": no_timestamp,
    }


def iso(value: Optional[dt.datetime]) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else "unknown"


def local_time(value: dt.datetime, timezone: ZoneInfo) -> str:
    return value.astimezone(timezone).strftime("%Y-%m-%d %H:%M:%S %Z")


def load_state(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def write_json_atomic(path: Path, value: dict[str, Any], mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_text_atomic(path: Path, text: str, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def teams_text(summary: str, max_bytes: int) -> str:
    """Keep the privacy-safe Teams summary below the message-size limit."""
    if len(summary.encode("utf-8")) <= max_bytes:
        return summary
    suffix = "\n\n[Full report remains on the Traefik host.]"
    available = max(1, max_bytes - len(suffix.encode("utf-8")))
    return summary.encode("utf-8")[:available].decode("utf-8", "ignore") + suffix


def teams_summary(
    period_events: list[dict[str, Any]],
    registrations: list[dict[str, Any]],
    by_site_journal: collections.Counter[tuple[str, str]],
    by_ip: dict[str, list[dict[str, Any]]],
    repeated: dict[str, list[dict[str, Any]]],
    cross_journal: dict[str, list[dict[str, Any]]],
    high_risk: list[dict[str, Any]],
    followed: list[dict[str, Any]],
    repeated_errors: list[list[dict[str, Any]]],
    start: dt.datetime,
    end: dt.datetime,
    timezone: ZoneInfo,
    coverage: dict[str, Any],
) -> str:
    """Create a useful Teams summary without user-level identifiers."""
    all_ips = set(by_ip) | {event["ip"] for event in high_risk}
    source_ids = {ip: f"source-{index:02d}" for index, ip in enumerate(sorted(all_ips), start=1)}
    submission_changes = sum(event["kind"] == "submission change request" for event in period_events)
    upload_attempts = sum(event["kind"] == "upload attempt" for event in period_events)
    activation_count = sum(event["kind"] == "activation observed activity" for event in period_events)
    login_count = sum(event["kind"] == "login observed activity" for event in period_events)
    submission_visits = sum(event["kind"] == "submission page visit" for event in period_events)

    lines = [
        "# OJS production registration activity summary",
        "",
        f"Reporting period: **{local_time(start, timezone)} through {local_time(end, timezone)}**",
        "",
        "## Summary",
        "",
        f"- Registration attempts: **{len(registrations)}** (observed POST requests)",
        f"- Distinct registration sources: **{len({event['ip'] for event in registrations})}**",
        f"- Activation requests observed: **{activation_count}**",
        f"- Login requests observed: **{login_count}**",
        f"- Submission page visits: **{submission_visits}**",
        f"- Submission-changing requests: **{submission_changes}**",
        f"- Upload attempts: **{upload_attempts}**",
        "",
        "### Registration attempts by site and journal",
        "",
        "| Site | Journal | Attempts |",
        "| --- | --- | ---: |",
    ]
    if by_site_journal:
        lines.extend(
            f"| {markdown_cell(site)} | {markdown_cell(journal)} | {count} |"
            for (site, journal), count in sorted(by_site_journal.items())
        )
    else:
        lines.append("| - | - | 0 |")

    lines.extend(["", "## Activity to review", ""])
    if repeated:
        lines.append("### Repeated registration attempts")
        lines.extend(
            f"- **{source_ids[ip]}**: {len(items)} attempts across {markdown_cell(', '.join(sorted({item['journal'] for item in items})))}"
            for ip, items in sorted(repeated.items())
        )
    if cross_journal:
        lines.append("### Cross-journal registration attempts")
        lines.extend(
            f"- **{source_ids[ip]}**: observed attempts across {markdown_cell(', '.join(sorted({item['journal'] for item in items})))}"
            for ip, items in sorted(cross_journal.items())
        )
    if high_risk:
        lines.append("### Upload and submission-changing requests")
        lines.extend(
            f"- {local_time(event['time'], timezone)} — **{source_ids.get(event['ip'], 'unassociated source')}** — {event['kind']} — {markdown_cell(event['site'])}/{markdown_cell(event['journal'])} — status `{markdown_cell(event['status'])}`"
            for event in high_risk[:100]
        )
    if followed:
        lines.append("### Registration followed by submission or upload activity")
        lines.append(f"- **{len(followed)}** qualifying follow-up requests were observed from recent registration sources.")
    if repeated_errors:
        lines.append("### Repeated errors")
        lines.append(
            f"- **{len(repeated_errors)}** repeated error groups ({sum(len(items) for items in repeated_errors)} requests) were observed."
        )
    if not repeated and not cross_journal and not high_risk and not repeated_errors:
        lines.append("No first-version review flags were observed in this period.")

    lines.extend([
        "",
        "## Coverage",
        "",
        f"- Matched log files: **{len(coverage['matched'])}**",
        f"- Invalid JSON lines: **{coverage['invalid_lines']}**",
        f"- Records without a usable timestamp: **{coverage['no_timestamp']}**",
        "",
        "Source labels are generated per report and cannot identify a person. Activation usernames, IP addresses, request paths, and activation tokens are intentionally omitted from this Teams summary.",
    ])
    return "\n".join(lines)


def send_to_teams(webhook_file: Path, report_text: str, max_bytes: int) -> None:
    try:
        webhook_url = webhook_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"Teams webhook secret could not be read: {exc}") from exc
    if not webhook_url:
        raise RuntimeError("Teams webhook secret is empty")

    payload = json.dumps({"text": teams_text(report_text, max_bytes)}).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError(f"Teams webhook returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Teams webhook returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Teams webhook request failed: {exc.reason}") from exc


def cleanup_reports(
    report_dir: Path,
    latest_path: Path,
    report_date: dt.date,
    retention_days: int,
) -> int:
    """Remove only dated reports produced by this collector.

    Keep the current report and the preceding retention_days - 1 calendar
    dates.  Unrecognised files and latest.md are intentionally left alone.
    """
    retention_days = max(1, retention_days)
    cutoff = report_date - dt.timedelta(days=retention_days - 1)
    deleted = 0
    for candidate in report_dir.glob("report-*.md"):
        if candidate == latest_path:
            continue
        match = REPORT_FILENAME.fullmatch(candidate.name)
        if not match:
            continue
        try:
            candidate_date = dt.date.fromisoformat(match.group(1))
        except ValueError:
            continue
        if candidate_date < cutoff:
            try:
                candidate.unlink()
                deleted += 1
            except OSError:
                continue
    return deleted


def markdown_cell(value: Any) -> str:
    return str(value if value not in (None, "") else "-").replace("|", "\\|").replace("\n", " ")


def event_line(event: dict[str, Any], timezone: ZoneInfo) -> str:
    detail = event["kind"]
    if event.get("username"):
        detail += f'; username={event["username"]}'
    return "| {} | {} | {} | {} | {} | {} | {} |".format(
        markdown_cell(local_time(event["time"], timezone)),
        markdown_cell(event["ip"]),
        markdown_cell(event["site"]),
        markdown_cell(event["journal"]),
        markdown_cell(f'{event["method"]} {event["path"]}'),
        markdown_cell(event["status"]),
        markdown_cell(detail),
    )


def report(
    events: list[dict[str, Any]],
    coverage: dict[str, Any],
    state: dict[str, Any],
    start: dt.datetime,
    end: dt.datetime,
    config: dict[str, Any],
) -> tuple[str, dict[str, Any], str]:
    timezone = ZoneInfo(str(config.get("report_timezone", "UTC")))
    period_events = sorted((event for event in events if start <= event["time"] <= end), key=lambda item: item["time"])
    registrations = [event for event in period_events if event["kind"] == "registration attempt"]
    registration_ips = {event["ip"] for event in registrations}
    activation_events = [event for event in period_events if event["kind"] == "activation observed activity"]
    submission_events = [
        event
        for event in period_events
        if event["kind"] in {"submission page visit", "submission change request", "upload attempt", "upload page or asset"}
    ]

    retention = dt.timedelta(days=int(config.get("registration_ip_retention_days", 7)))
    previous = state.get("registration_ips", {}) if isinstance(state.get("registration_ips", {}), dict) else {}
    recent_state: dict[str, Any] = {}
    registration_times: dict[str, list[dt.datetime]] = collections.defaultdict(list)
    for ip, details in previous.items():
        timestamp = parse_time(details.get("last_registration")) if isinstance(details, dict) else None
        if timestamp and timestamp >= end - retention:
            recent_state[ip] = details
            registration_times[ip].append(timestamp)
    for event in registrations:
        registration_times[event["ip"]].append(event["time"])
        recent_state[event["ip"]] = {
            "last_registration": iso(max(registration_times[event["ip"]])),
            "sites": sorted({item["site"] for item in registrations if item["ip"] == event["ip"]}),
            "journals": sorted({item["journal"] for item in registrations if item["ip"] == event["ip"]}),
        }
    tracked_ips = set(recent_state) | registration_ips
    timelines: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for event in period_events:
        if event["ip"] in tracked_ips and not is_asset(event["path"]):
            timelines[event["ip"]].append(event)

    by_site_journal: collections.Counter[tuple[str, str]] = collections.Counter(
        (event["site"], event["journal"]) for event in registrations
    )
    by_ip = collections.defaultdict(list)
    for event in registrations:
        by_ip[event["ip"]].append(event)
    repeated = {ip: items for ip, items in by_ip.items() if len(items) > 1}
    cross_journal = {ip: items for ip, items in by_ip.items() if len({item["journal"] for item in items}) > 1}

    high_risk = [
        event
        for event in period_events
        if event["kind"] in {"upload attempt", "submission change request"}
    ]
    followed = []
    for event in high_risk:
        prior_registrations = registration_times.get(event["ip"], [])
        if any(registration_time < event["time"] for registration_time in prior_registrations):
            followed.append(event)

    errors = [
        event
        for event in period_events
        if (event["status"] is not None and event["status"] >= 400) or event["kind"] == "malformed path"
    ]
    error_groups: collections.defaultdict[tuple[str, str, str, Optional[int]], list[dict[str, Any]]] = collections.defaultdict(list)
    for event in errors:
        if not is_asset(event["path"]):
            error_groups[(event["ip"], event["site"], event["path"], event["status"])].append(event)
    repeated_errors = sorted(
        (items for items in error_groups.values() if len(items) > 1),
        key=lambda items: (-len(items), items[0]["time"]),
    )

    report_lines = [
        "# OJS production registration activity report",
        "",
        f"Reporting period: **{local_time(start, timezone)} through {local_time(end, timezone)}**",
        "",
        "## Summary",
        "",
        f"- Registration attempts: **{len(registrations)}** (observed POST requests; not confirmed accounts created)",
        f"- Distinct registration IPs: **{len(registration_ips)}**",
        f"- Observed activation requests: **{sum(event['kind'] == 'activation observed activity' for event in period_events)}**",
        f"- Observed login requests: **{sum(event['kind'] == 'login observed activity' for event in period_events)}**",
        f"- Submission page visits: **{sum(event['kind'] == 'submission page visit' for event in period_events)}**",
        f"- Submission-changing requests: **{sum(event['kind'] == 'submission change request' for event in period_events)}**",
        f"- Upload attempts: **{sum(event['kind'] == 'upload attempt' for event in period_events)}**",
        f"- Upload pages or scripts observed: **{sum(event['kind'] == 'upload page or asset' for event in period_events)}** (not counted as upload attempts)",
        "",
        "### Registration attempts by site and journal",
        "",
        "| Site | Journal | Attempts |",
        "| --- | --- | ---: |",
    ]
    if by_site_journal:
        report_lines.extend(
            f"| {markdown_cell(site)} | {markdown_cell(journal)} | {count} |"
            for (site, journal), count in sorted(by_site_journal.items())
        )
    else:
        report_lines.append("| - | - | 0 |")

    report_lines.extend(["", "## Activity to review", ""])
    if not repeated and not cross_journal and not high_risk:
        report_lines.append("No first-version review flags were observed in this period.")
    if repeated:
        report_lines.extend(["### Repeated registration attempts", "", "These are repeated POST attempts from one IP, not proof of account creation.", ""])
        for ip, items in sorted(repeated.items()):
            journals = ", ".join(sorted({item["journal"] for item in items}))
            report_lines.append(f"- **{ip}**: {len(items)} attempts across {markdown_cell(journals)}")
    if cross_journal:
        report_lines.extend(["", "### Cross-journal registration attempts", ""])
        for ip, items in sorted(cross_journal.items()):
            journals = ", ".join(sorted({item["journal"] for item in items}))
            report_lines.append(f"- **{ip}**: observed registration POSTs for {markdown_cell(journals)}")
    if high_risk:
        report_lines.extend(["", "### Upload and submission-changing requests", "", "These are requests that may create or modify submission data; opening an upload page or downloading its scripts is not counted here.", ""])
        report_lines.extend(
            f"- {local_time(event['time'], timezone)} — `{event['ip']}` — {markdown_cell(event['site'])}/{markdown_cell(event['journal'])} — `{event['method']} {event['path']}` — status `{markdown_cell(event['status'])}`" + (" — registration IP" if event["ip"] in tracked_ips else "")
            for event in high_risk
        )
    if followed:
        report_lines.extend(["", "### Registration followed by submission or upload activity", ""])
        report_lines.extend(
            f"- {local_time(event['time'], timezone)} — `{event['ip']}` — {event['kind']} — {markdown_cell(event['site'])}/{markdown_cell(event['journal'])} — `{event['method']} {event['path']}`"
            for event in followed
        )
    report_lines.extend(["", "### Registration attempts observed", "", "| Time | IP | Site | Journal | Status |", "| --- | --- | --- | --- | ---: |"])
    if registrations:
        report_lines.extend(
            f"| {local_time(event['time'], timezone)} | `{event['ip']}` | {markdown_cell(event['site'])} | {markdown_cell(event['journal'])} | `{markdown_cell(event['status'])}` |"
            for event in registrations
        )
    else:
        report_lines.append("| - | - | - | - | - |")
    report_lines.extend(["", "### Account activation requests observed", "", "Activation tokens are omitted from this report.", "", "| Time | IP | Site | Journal | Username | Status |", "| --- | --- | --- | --- | --- | ---: |"])
    if activation_events:
        report_lines.extend(
            f"| {local_time(event['time'], timezone)} | `{event['ip']}` | {markdown_cell(event['site'])} | {markdown_cell(event['journal'])} | {markdown_cell(event['username'])} | `{markdown_cell(event['status'])}` |"
            for event in activation_events
        )
    else:
        report_lines.append("| - | - | - | - | - | - |")
    report_lines.extend(["", "### Submission and upload activity observed", "", "Upload page openings and static upload scripts are shown separately from actual upload attempts.", "", "| Time | IP | Site | Journal | Request | Status | Activity |", "| --- | --- | --- | --- | --- | ---: | --- |"])
    detail_limit = int(config.get("max_detail_events", 500))
    if submission_events:
        report_lines.extend(event_line(event, timezone) for event in submission_events[:detail_limit])
        if len(submission_events) > detail_limit:
            report_lines.append(f"\n_Only the first {detail_limit} submission/upload events are shown._")
    else:
        report_lines.append("| - | - | - | - | - | - | - |")
    if repeated_errors:
        report_lines.extend(["", "### Repeated errors and malformed paths", "", "Observed error clusters are listed for review; they are not automatically labeled suspicious.", ""])
        for items in repeated_errors[: int(config.get("max_error_groups", 100))]:
            first, last = items[0], items[-1]
            statuses = ", ".join(sorted({str(item["status"] or "unknown") for item in items}))
            report_lines.append(f"- **{len(items)}x** `{first['ip']}` — {markdown_cell(first['site'])} — `{first['path']}` — statuses `{statuses}` — {local_time(first['time'], timezone)} to {local_time(last['time'], timezone)}")

    report_lines.extend(["", "## Registration IP timelines", ""])
    if not timelines:
        report_lines.append("No registration IPs had non-routine requests in this reporting period.")
    for ip in sorted(timelines):
        report_lines.extend([
            f"### `{ip}`",
            "",
            "The IP association may represent more than one person or device.",
            "",
            "| Time | IP | Site | Journal | Request | Status | Observed activity |",
            "| --- | --- | --- | --- | --- | ---: | --- |",
        ])
        timeline_limit = int(config.get("max_timeline_events_per_ip", 500))
        for event in timelines[ip][:timeline_limit]:
            report_lines.append(event_line(event, timezone))
        if len(timelines[ip]) > timeline_limit:
            report_lines.append(f"\n_Only the first {timeline_limit} non-asset requests are shown for this IP._")

    report_lines.extend(["", "## Coverage", "", f"Log patterns: {', '.join(f'`{pattern}`' for pattern in coverage['patterns'])}", ""])
    if coverage["files"]:
        report_lines.extend(["| Log file | Lines | OJS events | Time range |", "| --- | ---: | ---: | --- |"])
        for item in coverage["files"]:
            range_text = f"{iso(item['first'])} to {iso(item['last'])}" if item["first"] else "no timestamped records"
            report_lines.append(f"| `{markdown_cell(item['file'])}` | {item['lines']} | {item['events']} | {range_text} |")
    else:
        report_lines.append("No files matched the configured log patterns.")
    if coverage["unreadable"]:
        report_lines.extend(["", "Unreadable files:"])
        report_lines.extend(f"- `{item['file']}`: {markdown_cell(item['error'])}" for item in coverage["unreadable"])
    report_lines.extend([
        "",
        f"- Matched log files: {len(coverage['matched'])}",
        f"- Invalid JSON lines: {coverage['invalid_lines']}",
        f"- Records without a usable timestamp: {coverage['no_timestamp']}",
        f"- Registration IP state retained for: {int(config.get('registration_ip_retention_days', 7))} days",
        "",
        "Interpretation notes: registration, activation, and login entries are observed requests. Status `200` alone is not a suspiciousness signal, and foreign IPs or main-site registrations are not automatically flagged.",
        "",
    ])
    teams_report = teams_summary(
        period_events,
        registrations,
        by_site_journal,
        by_ip,
        repeated,
        cross_journal,
        high_risk,
        followed,
        repeated_errors,
        start,
        end,
        timezone,
        coverage,
    )
    return "\n".join(report_lines), {
        "registration_ips": {
            ip: details
            for ip, details in recent_state.items()
            if parse_time(details.get("last_registration")) and parse_time(details.get("last_registration")) >= end - retention
        },
        "last_run": iso(end),
    }, teams_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/ojs-registration-report.json")
    parser.add_argument("--now", help="UTC ISO timestamp, primarily useful for tests")
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as handle:
        config = json.load(handle)

    end = parse_time(args.now) if args.now else dt.datetime.now(UTC)
    if end is None:
        raise SystemExit(f"invalid --now value: {args.now}")
    period_hours = int(config.get("report_period_hours", 24))
    start = end - dt.timedelta(hours=period_hours)
    events, coverage = read_logs(config.get("log_globs", []), config.get("sites", []))
    state_path = Path(config.get("state_file", "/var/lib/ojs-registration-report/state.json"))
    state = load_state(state_path)
    text, new_state, teams_report = report(events, coverage, state, start, end, config)

    timezone = ZoneInfo(str(config.get("report_timezone", "UTC")))
    report_dir = Path(config.get("report_dir", "/var/lib/ojs-registration-report/reports"))
    report_name = f"report-{end.astimezone(timezone):%Y-%m-%d}.md"
    report_path = report_dir / report_name
    latest_path = Path(config.get("latest_report", str(report_dir / "latest.md")))
    removed_reports = cleanup_reports(
        report_dir,
        latest_path,
        end.astimezone(timezone).date(),
        int(config.get("report_retention_days", 7)),
    )
    write_text_atomic(report_path, text)
    write_text_atomic(latest_path, text)
    write_json_atomic(state_path, new_state)
    if config.get("teams_enabled", False):
        send_to_teams(
            Path(config.get("teams_webhook_file", "/etc/ojs-registration-report/teams-webhook-url")),
            teams_report,
            int(config.get("teams_max_message_bytes", 28000)),
        )
        print("sent privacy-safe summary to Microsoft Teams")
    print(f"wrote {report_path}")
    print(f"removed old reports: {removed_reports}")
    print(f"registration attempts: {sum(event['kind'] == 'registration attempt' for event in events if start <= event['time'] <= end)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
