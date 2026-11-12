#!/usr/bin/env python3
"""Build a review-oriented report from Traefik JSON access logs.

The report deliberately describes registrations, activations, and logins as
observed requests.  A reverse proxy access log cannot prove that an account
was created, an email was confirmed, or a login succeeded.
"""

from __future__ import annotations

import argparse
import base64
import collections
import datetime as dt
import gzip
import glob
import ipaddress
import json
import os
import re
import struct
import tempfile
import urllib.error
import urllib.request
import zlib
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
TRAFFIC_FILENAME = re.compile(r"^traffic-(\d{4}-\d{2}-\d{2})\.png$")


def first_value(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in record and record[name] not in (None, ""):
            return record[name]
    return None


def parse_time(value: Any) -> Optional[dt.datetime]:
    if not value:
        return None
    text = str(value).strip()
    text = re.sub(
        r"(\d{2}:\d{2}:\d{2})\.(\d+)",
        lambda m: m.group(1) + "." + (m.group(2) + "000000")[:6],
        text,
    )
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


def write_binary_atomic(path: Path, data: bytes, mode: int = 0o640) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


FONT_5X7 = {
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
    "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
    "G": ("01111", "10000", "10000", "10111", "10001", "10001", "01111"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "I": ("11111", "00100", "00100", "00100", "00100", "00100", "11111"),
    "J": ("00111", "00010", "00010", "00010", "10010", "10010", "01100"),
    "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "M": ("10001", "11011", "10101", "10101", "10001", "10001", "10001"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
    "Q": ("01110", "10001", "10001", "10001", "10101", "10010", "01101"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "V": ("10001", "10001", "10001", "10001", "10001", "01010", "00100"),
    "W": ("10001", "10001", "10001", "10101", "10101", "11011", "10001"),
    "X": ("10001", "10001", "01010", "00100", "01010", "10001", "10001"),
    "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
    "Z": ("11111", "00001", "00010", "00100", "01000", "10000", "11111"),
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "3": ("11110", "00001", "00001", "01110", "00001", "00001", "11110"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "5": ("11111", "10000", "10000", "11110", "00001", "00001", "11110"),
    "6": ("01110", "10000", "10000", "11110", "10001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
    "9": ("01110", "10001", "10001", "01111", "00001", "00001", "01110"),
    " ": ("00000",) * 7,
    ".": ("00000",) * 6 + ("00100",),
    ":": ("00000", "00100", "00100", "00000", "00100", "00100", "00000"),
    "/": ("00001", "00010", "00010", "00100", "01000", "01000", "10000"),
    "-": ("00000", "00000", "00000", "11111", "00000", "00000", "00000"),
    "(": ("00010", "00100", "01000", "01000", "01000", "00100", "00010"),
    ")": ("01000", "00100", "00010", "00010", "00010", "00100", "01000"),
    ",": ("00000", "00000", "00000", "00000", "00000", "00100", "01000"),
    "?": ("01110", "10001", "00001", "00010", "00100", "00000", "00100"),
}


def chart_png(
    width: int,
    height: int,
    series: list[list[int]],
    site_names: list[str],
    x_labels: list[str],
) -> bytes:
    """Create a labeled, dependency-free line chart as an RGB PNG."""
    width = min(1024, max(320, int(width)))
    height = min(1024, max(180, int(height)))
    pixels = bytearray([255] * (width * height * 3))

    def pixel(x: int, y: int, color: tuple[int, int, int]) -> None:
        if 0 <= x < width and 0 <= y < height:
            offset = (y * width + x) * 3
            pixels[offset : offset + 3] = bytes(color)

    def rectangle(x: int, y: int, rectangle_width: int, rectangle_height: int, color: tuple[int, int, int]) -> None:
        for yy in range(y, y + rectangle_height):
            for xx in range(x, x + rectangle_width):
                pixel(xx, yy, color)

    def text(x: int, y: int, value: str, color: tuple[int, int, int], scale: int = 1) -> None:
        cursor = x
        for character in value.upper():
            glyph = FONT_5X7.get(character, FONT_5X7["?"])
            for row, bits in enumerate(glyph):
                for column, bit in enumerate(bits):
                    if bit == "1":
                        rectangle(cursor + column * scale, y + row * scale, scale, scale, color)
            cursor += 6 * scale

    def line(x1: int, y1: int, x2: int, y2: int, color: tuple[int, int, int], thickness: int = 1) -> None:
        dx = abs(x2 - x1)
        dy = abs(y2 - y1)
        steps = max(dx, dy, 1)
        for step in range(steps + 1):
            x = round(x1 + (x2 - x1) * step / steps)
            y = round(y1 + (y2 - y1) * step / steps)
            radius = thickness // 2
            for yy in range(y - radius, y + radius + 1):
                for xx in range(x - radius, x + radius + 1):
                    pixel(xx, yy, color)

    title_scale = 2 if width >= 440 else 1
    title = "OJS REQUESTS / HOUR - LAST 24H"
    margin_left, margin_right = 42, 14
    legend_top = 24 if title_scale == 2 else 18
    legend_row_height = 10
    margin_top = max(58, legend_top + len(site_names) * legend_row_height + 8)
    margin_bottom = 34
    plot_width = width - margin_left - margin_right
    plot_height = height - margin_top - margin_bottom
    max_value = max((value for values in series for value in values), default=0)
    scale = max(1, max_value)
    grid = (226, 230, 235)
    axis = (120, 128, 138)
    label = (74, 82, 92)
    text(8, 4, title, (35, 43, 52), title_scale)

    colors = [(31, 111, 235), (222, 79, 58), (39, 148, 90), (151, 91, 201), (214, 137, 32)]
    for index, site_name in enumerate(site_names):
        color = colors[index % len(colors)]
        legend_y = legend_top + index * legend_row_height
        rectangle(8, legend_y + 2, 8, 6, color)
        text(20, legend_y, site_name, label, 1)

    for row in range(6):
        y = margin_top + round(plot_height * row / 5)
        line(margin_left, y, width - margin_right, y, grid)
        tick_value = round(max_value * (5 - row) / 5)
        tick_text = f"{tick_value:,}"
        text(max(1, margin_left - len(tick_text) * 6 - 4), y - 3, tick_text, label, 1)
    text(3, margin_top - 15, "REQUESTS", label, 1)
    point_count = max((len(values) for values in series), default=0)
    if point_count > 1:
        for column in range(point_count):
            x = margin_left + round(plot_width * column / (point_count - 1))
            line(x, margin_top, x, height - margin_bottom, grid)
        label_indices = sorted({round(index * (point_count - 1) / 5) for index in range(6)})
        for index in label_indices:
            x = margin_left + round(plot_width * index / (point_count - 1))
            value = x_labels[index] if index < len(x_labels) else ""
            text(max(margin_left, x - len(value) * 3), height - margin_bottom + 9, value, label, 1)
    line(margin_left, margin_top, margin_left, height - margin_bottom, axis, 2)
    line(margin_left, height - margin_bottom, width - margin_right, height - margin_bottom, axis, 2)

    for index, values in enumerate(series):
        if not values:
            continue
        color = colors[index % len(colors)]
        points = []
        for point, value in enumerate(values):
            x = margin_left if len(values) == 1 else margin_left + round(plot_width * point / (len(values) - 1))
            y = height - margin_bottom - round(plot_height * value / scale)
            points.append((x, y))
        for first, second in zip(points, points[1:]):
            line(*first, *second, color, 4)
        for x, y in points:
            line(x - 3, y, x + 3, y, color, 5)
            line(x, y - 3, x, y + 3, color, 5)

    rows = b"".join(b"\x00" + pixels[row * width * 3 : (row + 1) * width * 3] for row in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + png_chunk(b"IDAT", zlib.compress(rows, 6))
        + png_chunk(b"IEND", b"")
    )


def traffic_graph_png(
    width: int,
    height: int,
    series: list[list[int]],
    site_names: list[str],
    x_labels: list[str],
    max_bytes: int,
) -> bytes:
    """Render the chart, shrinking it until it fits the Teams payload budget."""
    width = min(1024, max(320, int(width)))
    height = min(1024, max(180, int(height)))
    max_bytes = max(2000, int(max_bytes))
    while True:
        graph = chart_png(width, height, series, site_names, x_labels)
        if len(graph) <= max_bytes or (width == 320 and height == 180):
            return graph
        width = max(320, width * 3 // 4)
        height = max(180, height * 3 // 4)


def traffic_summary(
    events: list[dict[str, Any]],
    start: dt.datetime,
    end: dt.datetime,
    sites: list[dict[str, Any]],
    timezone: ZoneInfo,
) -> dict[str, Any]:
    site_names = [str(site.get("name")) for site in sites if site.get("name")]
    site_names.extend(sorted({event["site"] for event in events if event["site"] not in site_names}))
    first_hour = start.replace(minute=0, second=0, microsecond=0)
    last_hour = end.replace(minute=0, second=0, microsecond=0)
    hours = []
    current = first_hour
    while current <= last_hour:
        hours.append(current)
        current += dt.timedelta(hours=1)

    counts = {hour: collections.Counter({site: 0 for site in site_names}) for hour in hours}
    for event in events:
        if not start <= event["time"] <= end:
            continue
        bucket = event["time"].replace(minute=0, second=0, microsecond=0)
        if bucket in counts:
            counts[bucket][event["site"]] += 1

    totals = {hour: sum(counts[hour].values()) for hour in hours}
    peak_hour = max(hours, key=lambda hour: (totals[hour], hour), default=None)
    return {
        "sites": site_names,
        "hours": hours,
        "counts": counts,
        "totals": totals,
        "peak_hour": peak_hour,
        "peak_total": totals.get(peak_hour, 0) if peak_hour else 0,
        "timezone": timezone,
    }


def hour_label(value: dt.datetime, timezone: ZoneInfo) -> str:
    return value.astimezone(timezone).strftime("%Y-%m-%d %I:00 %p %Z")


def traffic_text(traffic: Optional[dict[str, Any]], compact: bool = False) -> list[str]:
    if not traffic:
        return []
    peak_hour = traffic["peak_hour"]
    lines = ["**Traffic overview**" if compact else "## Traffic overview", ""]
    if peak_hour is None:
        lines.append("- No requests were observed for the configured OJS sites.")
        return lines
    for site in traffic["sites"]:
        peak = max(traffic["hours"], key=lambda hour: (traffic["counts"][hour][site], hour), default=None)
        site_total = sum(traffic["counts"][hour][site] for hour in traffic["hours"])
        peak_count = traffic["counts"][peak][site] if peak else 0
        lines.append(
            f"- {markdown_cell(site)}: **{site_total:,} requests**; busiest hour: "
            f"**{hour_label(peak, traffic['timezone'])}** ({peak_count:,} requests)"
            if peak else f"- {markdown_cell(site)}: **0** requests"
        )
    return lines


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
    traffic: Optional[dict[str, Any]],
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
        "**OJS production registration activity summary**",
        "",
        f"Reporting period: **{local_time(start, timezone)} through {local_time(end, timezone)}**",
        "",
    ]
    if traffic:
        lines.extend([*traffic_text(traffic, compact=True), ""])
    lines.extend([
        "**Summary**",
        "",
        f"- Registration attempts: **{len(registrations)}** (observed POST requests)",
        f"- Distinct registration sources: **{len({event['ip'] for event in registrations})}**",
        f"- Activation requests observed: **{activation_count}**",
        f"- Login requests observed: **{login_count}**",
        f"- Submission page visits: **{submission_visits}**",
        f"- Submission-changing requests: **{submission_changes}**",
        f"- Upload attempts: **{upload_attempts}**",
        "",
        "**Registration attempts by site and journal**",
        "",
        "| Site | Journal | Attempts |",
        "| --- | --- | ---: |",
    ])
    if by_site_journal:
        lines.extend(
            f"| {markdown_cell(site)} | {markdown_cell(journal)} | {count} |"
            for (site, journal), count in sorted(by_site_journal.items())
        )
    else:
        lines.append("| - | - | 0 |")

    lines.extend(["", "**Activity to review**", ""])
    if repeated:
        lines.append("**Repeated registration attempts**")
        lines.extend(
            f"- **{source_ids[ip]}**: {len(items)} attempts across {markdown_cell(', '.join(sorted({item['journal'] for item in items})))}"
            for ip, items in sorted(repeated.items())
        )
    if cross_journal:
        lines.append("**Cross-journal registration attempts**")
        lines.extend(
            f"- **{source_ids[ip]}**: observed attempts across {markdown_cell(', '.join(sorted({item['journal'] for item in items})))}"
            for ip, items in sorted(cross_journal.items())
        )
    if high_risk:
        lines.append("**Upload and submission-changing requests**")
        lines.extend(
            f"- {local_time(event['time'], timezone)} — **{source_ids.get(event['ip'], 'unassociated source')}** — {event['kind']} — {markdown_cell(event['site'])}/{markdown_cell(event['journal'])} — status `{markdown_cell(event['status'])}`"
            for event in high_risk[:100]
        )
    if followed:
        lines.append("**Registration followed by submission or upload activity**")
        lines.append(f"- **{len(followed)}** qualifying follow-up requests were observed from recent registration sources.")
    if repeated_errors:
        lines.append("**Repeated errors**")
        lines.append(
            f"- **{len(repeated_errors)}** repeated error groups ({sum(len(items) for items in repeated_errors)} requests) were observed."
        )
    if not repeated and not cross_journal and not high_risk and not repeated_errors:
        lines.append("No first-version review flags were observed in this period.")

    lines.extend([
        "",
        "**Coverage**",
        "",
        f"- Matched log files: **{len(coverage['matched'])}**",
        f"- Invalid JSON lines: **{coverage['invalid_lines']}**",
        f"- Records without a usable timestamp: **{coverage['no_timestamp']}**",
        "",
        "Source labels are generated per report and cannot identify a person. Activation usernames, IP addresses, request paths, and activation tokens are intentionally omitted from this Teams summary.",
    ])
    return "\n".join(lines)


def send_to_teams(
    webhook_file: Path,
    report_text: str,
    max_bytes: int,
    graph_path: Optional[Path] = None,
) -> None:
    try:
        webhook_url = webhook_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(f"Teams webhook secret could not be read: {exc}") from exc
    if not webhook_url:
        raise RuntimeError("Teams webhook secret is empty")

    if graph_path:
        try:
            graph = base64.b64encode(graph_path.read_bytes()).decode("ascii")
        except OSError as exc:
            raise RuntimeError(f"traffic graph could not be read: {exc}") from exc
        # Reserve space for the card wrapper and the inline base64 image so a
        # long review summary cannot make the whole Teams entity too large.
        summary_budget = max(1000, max_bytes - len(graph) - 2048)
        summary = teams_text(report_text, summary_budget)
        payload_value: dict[str, Any] = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.2",
                    "body": [
                        {
                            "type": "Image",
                            "url": f"data:image/png;base64,{graph}",
                            "altText": "OJS requests per hour during the reporting period",
                            "size": "Stretch",
                        },
                        {"type": "TextBlock", "text": summary, "wrap": True},
                    ],
                },
            }],
        }
    else:
        summary = teams_text(report_text, max_bytes)
        payload_value = {"text": summary}
    payload = json.dumps(payload_value).encode("utf-8")
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


def cleanup_traffic_graphs(
    graph_dir: Path,
    latest_path: Path,
    report_date: dt.date,
    retention_days: int,
) -> int:
    retention_days = max(1, retention_days)
    cutoff = report_date - dt.timedelta(days=retention_days - 1)
    deleted = 0
    for candidate in graph_dir.glob("traffic-*.png"):
        if candidate == latest_path:
            continue
        match = TRAFFIC_FILENAME.fullmatch(candidate.name)
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
) -> tuple[str, dict[str, Any], str, Optional[dict[str, Any]]]:
    timezone = ZoneInfo(str(config.get("report_timezone", "UTC")))
    period_events = sorted((event for event in events if start <= event["time"] <= end), key=lambda item: item["time"])
    traffic = traffic_summary(
        period_events,
        start,
        end,
        config.get("sites", []),
        timezone,
    ) if config.get("traffic_enabled", False) else None
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

    if traffic:
        report_lines.extend(["", *traffic_text(traffic)])

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
        traffic,
    )
    return "\n".join(report_lines), {
        "registration_ips": {
            ip: details
            for ip, details in recent_state.items()
            if parse_time(details.get("last_registration")) and parse_time(details.get("last_registration")) >= end - retention
        },
        "last_run": iso(end),
    }, teams_report, traffic


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
    text, new_state, teams_report, traffic = report(events, coverage, state, start, end, config)

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
    graph_path = None
    removed_graphs = 0
    if traffic:
        graph_dir = Path(config.get("traffic_dir", str(report_dir / "traffic")))
        graph_name = f"traffic-{end.astimezone(timezone):%Y-%m-%d}.png"
        graph_path = graph_dir / graph_name
        latest_graph_path = Path(config.get("latest_traffic", str(graph_dir / "latest-traffic.png")))
        removed_graphs = cleanup_traffic_graphs(
            graph_dir,
            latest_graph_path,
            end.astimezone(timezone).date(),
            int(config.get("report_retention_days", 7)),
        )
        series = [[traffic["counts"][hour][site] for hour in traffic["hours"]] for site in traffic["sites"]]
        graph = traffic_graph_png(
            int(config.get("traffic_width", 1200)),
            int(config.get("traffic_height", 600)),
            series,
            traffic["sites"],
            [hour.astimezone(traffic["timezone"]).strftime("%I%p").lstrip("0") for hour in traffic["hours"]],
            int(config.get("traffic_max_png_bytes", 8000)),
        )
        write_binary_atomic(graph_path, graph)
        write_binary_atomic(latest_graph_path, graph)
    if config.get("teams_enabled", False):
        send_to_teams(
            Path(config.get("teams_webhook_file", "/etc/ojs-registration-report/teams-webhook-url")),
            teams_report,
            int(config.get("teams_max_message_bytes", 28000)),
            Path(config.get("latest_traffic", str(graph_path))) if traffic else None,
        )
        print("sent privacy-safe summary to Microsoft Teams")
    print(f"wrote {report_path}")
    print(f"removed old reports: {removed_reports}")
    if traffic:
        print(f"wrote {graph_path}")
        print(f"removed old traffic graphs: {removed_graphs}")
        if traffic["peak_hour"]:
            print(f"busiest hour: {hour_label(traffic['peak_hour'], timezone)} ({traffic['peak_total']:,} requests)")
    print(f"registration attempts: {sum(event['kind'] == 'registration attempt' for event in events if start <= event['time'] <= end)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
