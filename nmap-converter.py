#!/usr/bin/env python3
"""nmap-converter-ng: convert nmap reports (XML, .nmap, .gnmap) to XLSX or CSV.

Rewritten modern version of nmap-converter.py.
No dependency on the abandoned python-libnmap package.
Requires `xlsxwriter` only for XLSX output (CSV output is stdlib-only).
"""

import argparse
import csv
import os
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

try:
    from xlsxwriter import Workbook
except ImportError:  # xlsxwriter is required only for XLSX output
    Workbook = None


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class Service:
    def __init__(self, port="", protocol="", state="", service="",
                 product="", version="", extrainfo="", reason="",
                 tunnel="", confidence=""):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service
        self.product = product
        self.version = version
        self.extrainfo = extrainfo
        self.reason = reason
        self.tunnel = tunnel
        self.confidence = confidence

    def row(self, host):
        return [
            host.hostname, host.ip, self.port, self.protocol, self.state,
            self.service, self.tunnel, self.product, self.version,
            self.extrainfo, self.reason,
        ]


class Host:
    def __init__(self, hostname="", ip="", status="", os_str="", addresses=None):
        self.hostname = hostname
        self.ip = ip
        self.status = status
        self.os_str = os_str
        self.addresses = addresses or {}   # addrtype -> addr
        self.services = []
        self.scripts = []                  # list of (script_id, script_output)

    def summary_services_count(self):
        return len(self.services)


class Report:
    def __init__(self, basename="N/A"):
        self.basename = basename
        self.command = "N/A"
        self.version = "N/A"
        self.scan_type = "N/A"
        self.started = "N/A"
        self.completed = "N/A"
        self.hosts_total = "N/A"
        self.hosts_up = "N/A"
        self.hosts_down = "N/A"
        self.hosts = []


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(path):
    """Return 'xml', 'gnmap', 'nmap' (text) or None."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".xml":
        return "xml"
    if ext == ".gnmap":
        return "gnmap"
    if ext == ".nmap":
        return "nmap"
    # sniff the content
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if head.lstrip().startswith("<?xml") or "<nmaprun" in head:
        return "xml"
    if re.search(r"^Host: .*\t(Ports|Status): ", head, re.M):
        return "gnmap"
    if "Nmap scan report for" in head or re.search(r"^\d+/tcp\s+\w+", head, re.M):
        return "nmap"
    return None


# ---------------------------------------------------------------------------
# XML parser
# ---------------------------------------------------------------------------

def _xml_ts(elem, attr):
    val = elem.get(attr)
    if val:
        try:
            return datetime.fromtimestamp(int(val), tz=timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S (UTC)")
        except (ValueError, OverflowError, OSError):
            pass
    return "N/A"


def _xml_hostname(host_elem):
    names = [hn.get("name", "") for hn in host_elem.findall("hostnames/hostname")
             if hn.get("name")]
    return names[0] if names else ""


def _xml_os_string(host_elem):
    parts = []
    for osc in host_elem.findall("os/osclass"):
        vendor = osc.get("vendor", "")
        family = osc.get("osfamily", "")
        gen = osc.get("osgen", "")
        acc = osc.get("accuracy", "")
        s = "{}, {}".format(vendor, family)
        if gen:
            s += " ({})".format(gen)
        parts.append("{} ({}%)".format(s, acc))
    return " | ".join(parts)


def _xml_service_from(port_elem):
    state_elem = port_elem.find("state")
    svc_elem = port_elem.find("service")
    svc = Service(
        port=port_elem.get("portid", ""),
        protocol=port_elem.get("protocol", ""),
        state=(state_elem.get("state", "") if state_elem is not None else ""),
        reason=(state_elem.get("reason", "") if state_elem is not None else ""),
    )
    if svc_elem is not None:
        svc.service = svc_elem.get("name", "")
        svc.tunnel = svc_elem.get("tunnel", "")
        svc.product = svc_elem.get("product", "")
        svc.version = svc_elem.get("version", "")
        svc.extrainfo = svc_elem.get("extrainfo", "")
        method = svc_elem.get("method", "")
        conf = svc_elem.get("conf", "0")
        try:
            svc.confidence = float(conf) / 10
        except ValueError:
            svc.confidence = conf
        if method:
            svc.service = "{} ({})".format(svc.service, method) if svc.service else method
    return svc


def _parse_xml_report(path):
    tree = ET.parse(path)
    root = tree.getroot()
    report = Report(basename=os.path.basename(path))

    report.command = root.get("args", "N/A")
    report.version = root.get("version", "N/A")
    report.scan_type = "N/A"

    for host_elem in root.findall("host"):
        host = Host()
        status = host_elem.find("status")
        host.status = status.get("state", "") if status is not None else ""

        for addr in host_elem.findall("address"):
            atype = addr.get("addrtype", "")
            host.addresses[atype] = addr.get("addr", "")
        if "ipv4" in host.addresses:
            host.ip = host.addresses["ipv4"]
        elif "ipv6" in host.addresses:
            host.ip = host.addresses["ipv6"]
        else:
            host.ip = next(iter(host.addresses.values()), "")

        host.hostname = _xml_hostname(host_elem)
        host.os_str = _xml_os_string(host_elem)

        for script in host_elem.findall("hostscript/script"):
            host.scripts.append((script.get("id", ""),
                                 (script.get("output") or "").strip()))

        for port_elem in host_elem.findall("ports/port"):
            svc = _xml_service_from(port_elem)
            for script in port_elem.findall("script"):
                host.scripts.append((script.get("id", ""),
                                     (script.get("output") or "").strip()))
            host.services.append(svc)

        report.hosts.append(host)

    runstats = root.find("runstats")
    if runstats is not None:
        finished = runstats.find("finished")
        if finished is not None:
            report.completed = _xml_ts(finished, "time")
            report.command = finished.get("command", report.command) or report.command
        hosts_elem = runstats.find("hosts")
        if hosts_elem is not None:
            report.hosts_total = hosts_elem.get("total", "N/A")
            report.hosts_up = hosts_elem.get("up", "N/A")
            report.hosts_down = hosts_elem.get("down", "N/A")

    report.started = _xml_ts(root, "startstr" if root.get("startstr") else "start")
    if report.started == "N/A":
        report.started = _xml_ts(root, "start")
    return report


# ---------------------------------------------------------------------------
# gnmap (grepable) parser
# ---------------------------------------------------------------------------

_HOST_PORTS_RE = re.compile(r"^Host:\s+(?P<addr>\S+)(?:\s+\((?P<hostname>[^)]*)\))?"
                            r"\tPorts:\s+(?P<ports>\S.*)$")
_HOST_STATUS_RE = re.compile(r"^Host:\s+(?P<addr>\S+)(?:\s+\((?P<hostname>[^)]*)\))?"
                             r"\tStatus:\s+(?P<status>\S+)")
_HEADER_RE = re.compile(r"^# Nmap (?P<version>[\d.]+) scan initiated "
                        r"(?P<date>.+?) as: (?P<command>.+)$")
_DONE_RE = re.compile(r"^# Nmap done at (?P<date>.+?) -- (?P<stats>.+)$")


def _gnmap_service(entry):
    # 22/open/tcp//ssh//OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)/
    fields = entry.split("/")
    try:
        port = fields[0]
        state = fields[1]
        protocol = fields[2] if len(fields) > 2 else ""
        service = fields[4] if len(fields) > 4 else ""
    except IndexError:
        return None
    rest = fields[6] if len(fields) > 6 else ""
    product, version, extrainfo = _split_product_info(rest)
    return Service(port=port, protocol=protocol, state=state, service=service,
                   product=product, version=version, extrainfo=extrainfo)


def _split_product_info(rest):
    """Split nmap version-info string into (product, version, extrainfo).

    nmap renders it as `product version (extrainfo)`, e.g.
    `OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7 (Ubuntu Linux; protocol 2.0)`.
    """
    product = version = ""
    extrainfo = ""
    if not rest:
        return product, version, extrainfo
    # pull out parenthesized extrainfo chunks
    while True:
        extra_m = re.search(r"\(([^()]*)\)", rest)
        if not extra_m:
            break
        extrainfo = " ".join([extrainfo, extra_m.group(1)]).strip()
        rest = (rest[:extra_m.start()] + rest[extra_m.end():]).strip()
    tokens = rest.split()
    while tokens and not re.search(r"\d", tokens[0]):
        product = (product + " " + tokens.pop(0)).strip()
    if tokens:
        version = tokens.pop(0)
        extrainfo = " ".join([" ".join(tokens), extrainfo]).strip()
    return product, version, extrainfo


def _gnmap_parse_stats(stats):
    # "1 IP address (1 host up) scanned in 29.39 seconds"
    total = up = down = "N/A"
    m = re.search(r"(\d+) IP address", stats)
    if m:
        total = m.group(1)
    m = re.search(r"\((\d+) host[s]? up\)", stats)
    if m:
        up = m.group(1)
        try:
            down = str(int(total) - int(up)) if total != "N/A" else "N/A"
        except ValueError:
            pass
    return total, up, down


def _parse_gnmap_report(path):
    report = Report(basename=os.path.basename(path))
    hosts_by_addr = {}

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue

            m = _HEADER_RE.match(line)
            if m:
                report.version = m.group("version")
                report.command = m.group("command")
                report.started = m.group("date")
                report.scan_type = "N/A"
                continue

            m = _DONE_RE.match(line)
            if m:
                report.completed = m.group("date")
                total, up, down = _gnmap_parse_stats(m.group("stats"))
                report.hosts_total, report.hosts_up, report.hosts_down = total, up, down
                continue

            m = _HOST_STATUS_RE.match(line)
            if m:
                addr = m.group("addr")
                host = hosts_by_addr.setdefault(addr, Host(ip=addr))
                if m.group("hostname"):
                    host.hostname = m.group("hostname")
                host.status = m.group("status")
                continue

            m = _HOST_PORTS_RE.match(line)
            if m:
                addr = m.group("addr")
                host = hosts_by_addr.setdefault(addr, Host(ip=addr))
                if m.group("hostname"):
                    host.hostname = m.group("hostname")
                for entry in m.group("ports").split(", "):
                    svc = _gnmap_service(entry.strip())
                    if svc is not None:
                        host.services.append(svc)
                continue

    report.hosts = list(hosts_by_addr.values())
    return report


# ---------------------------------------------------------------------------
# .nmap (plain text) parser — best effort
# ---------------------------------------------------------------------------

_PORT_LINE_RE = re.compile(
    r"^(?P<port>\d+)/(?P<proto>tcp|udp|sctp)\s+(?P<state>\S+)\s+(?P<rest>.*)$")
_OPEN_FILTERED = {"open", "filtered", "closed", "unfiltered",
                  "open|filtered", "closed|filtered"}
_REASON_TOKENS = {"syn-ack", "syn", "ack", "reset", "no-response", "echo-reply",
                  "ttl", "proto", "conn-refused", "echo-resp", "arp-response"}


def _parse_nmap_text_report(path):
    report = Report(basename=os.path.basename(path))
    host = None

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            m = re.match(r"^Nmap scan report for (.+)$", line)
            if m:
                target = m.group(1).strip()
                ip = ""
                ipm = re.search(r"\(([^)]+)\)\s*$", target)
                if ipm:
                    ip = ipm.group(1)
                    target = target[:ipm.start()].strip()
                host = Host(hostname=target, ip=ip)
                report.hosts.append(host)
                continue

            if host is None:
                continue

            m = re.match(r"^Host is (up|down)(?:.*\(([\d.]+)s latency\))?", line)
            if m:
                host.status = "up" if m.group(1) == "up" else "down"
                continue

            pm = _PORT_LINE_RE.match(line)
            if pm and pm.group("state") in _OPEN_FILTERED:
                rest = pm.group("rest").split()
                service = rest[0] if rest else ""
                rest = rest[1:]
                # optional REASON column (nmap --reason), e.g. `syn-ack ttl 52`
                reason = ""
                while rest and (
                        rest[0] in _REASON_TOKENS
                        or (reason.endswith("ttl") and re.match(r"^\d+$", rest[0]))):
                    reason = (reason + " " + rest.pop(0)).strip()
                rest_str = " ".join(rest).strip()
                product, version, extrainfo = _split_product_info(rest_str)
                host.services.append(Service(
                    port=pm.group("port"), protocol=pm.group("proto"),
                    state=pm.group("state"), service=service,
                    product=product, version=version, extrainfo=extrainfo,
                    reason=reason))
                continue

            m = re.match(r"^Service Info: OS: (.+?)(?:; CPE: .+)?$", line)
            if m and host.services:
                # keep OS info on the host row via os_str
                host.os_str = m.group(1).strip()
                continue

    return report


# ---------------------------------------------------------------------------
# Public parse entry point
# ---------------------------------------------------------------------------

def parse_report(path):
    fmt = detect_format(path)
    if fmt == "xml":
        return _parse_xml_report(path)
    if fmt == "gnmap":
        return _parse_gnmap_report(path)
    if fmt == "nmap":
        return _parse_nmap_text_report(path)
    raise ValueError("cannot determine input format of {!r}".format(path))


# ---------------------------------------------------------------------------
# XLSX output
# ---------------------------------------------------------------------------

RESULTS_HEADER = ["Host", "IP", "Port", "Protocol", "State", "Service",
                  "Tunnel", "Product", "Version", "Extra", "Reason"]


def _fmt_bold(wb):
    return wb.add_format({"bold": True})


def write_xlsx(reports, output):
    if Workbook is None:
        sys.exit("error: xlsxwriter is not installed. "
                 "Install it with: pip install xlsxwriter "
                 "(or use CSV output: --format csv)")

    workbook = Workbook(output)
    fmt_bold = _fmt_bold(workbook)

    # --- Summary sheet ---
    ws = workbook.add_worksheet("Summary")
    header = ["Scan", "Command", "Version", "Scan Type", "Started",
              "Completed", "Hosts Total", "Hosts Up", "Hosts Down"]
    for idx, item in enumerate(header):
        ws.write(0, idx, item, fmt_bold)
    row = 1
    for report in reports:
        values = [report.basename, report.command, report.version,
                  report.scan_type, report.started, report.completed,
                  report.hosts_total, report.hosts_up, report.hosts_down]
        for idx, value in enumerate(values):
            ws.write(row, idx, value)
        row += 1

    # --- Hosts sheet ---
    ws = workbook.add_worksheet("Hosts")
    header = ["Host", "IP", "Status", "Services", "OS"]
    for idx, item in enumerate(header):
        ws.write(0, idx, item, fmt_bold)
    row = 1
    for report in reports:
        for host in report.hosts:
            values = [host.hostname, host.ip, host.status,
                      host.summary_services_count(), host.os_str]
            for idx, value in enumerate(values):
                ws.write(row, idx, value)
            row += 1
    ws.autofilter(0, 0, row, len(header) - 1)
    ws.freeze_panes(1, 0)

    # --- Results sheet ---
    ws = workbook.add_worksheet("Results")
    for idx, item in enumerate(RESULTS_HEADER):
        ws.write(0, idx, item, fmt_bold)
    row = 1
    for report in reports:
        for host in report.hosts:
            for script_id, script_out in host.scripts:
                values = [host.hostname, host.ip, "", "", "", "", "",
                          "", "", "", script_id + ": " + script_out]
                for idx, value in enumerate(values):
                    ws.write(row, idx, value)
                row += 1
            for svc in host.services:
                for idx, value in enumerate(svc.row(host)):
                    ws.write(row, idx, value)
                row += 1
    ws.autofilter(0, 0, row, len(RESULTS_HEADER) - 1)
    ws.freeze_panes(1, 0)

    workbook.close()


# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------

def write_csv(reports, output):
    with open(output, "w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["Report"] + RESULTS_HEADER)
        for report in reports:
            for host in report.hosts:
                for script_id, script_out in host.scripts:
                    writer.writerow([report.basename, host.hostname, host.ip,
                                     "", "", "", "", "", "", "", "",
                                     script_id + ": " + script_out])
                for svc in host.services:
                    writer.writerow([report.basename] + svc.row(host))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def choose_format(output, requested):
    if requested != "auto":
        return requested
    if output is None:
        return "xlsx"
    ext = os.path.splitext(output)[1].lower()
    if ext == ".csv":
        return "csv"
    if ext in (".xlsx", ".xlsm", ".xls"):
        return "xlsx"
    return "xlsx"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="nmap-converter",
        description="Convert nmap reports (.xml, .nmap, .gnmap) to XLSX or CSV.")
    parser.add_argument("reports", metavar="REPORT", nargs="+",
                        help="path to nmap report (xml, nmap or gnmap; "
                             "format is auto-detected)")
    parser.add_argument("-o", "--output", metavar="FILE", default=None,
                        help="path to output file (default: converted.xlsx "
                             "or converted.csv depending on --format)")
    parser.add_argument("-f", "--format", choices=["xlsx", "csv", "auto"],
                        default="auto",
                        help="output format (default: auto — derived from "
                             "output file extension, otherwise xlsx)")
    args = parser.parse_args(argv)

    out_format = choose_format(args.output, args.format)
    if args.output is None:
        args.output = "converted." + ("csv" if out_format == "csv" else "xlsx")

    reports = []
    for path in args.reports:
        if not os.path.isfile(path):
            sys.exit("error: file not found: {}".format(path))
        try:
            report = parse_report(path)
        except (ValueError, ET.ParseError) as ex:
            sys.exit("error: cannot parse {}: {}".format(path, ex))
        reports.append(report)

    if out_format == "csv":
        write_csv(reports, args.output)
    else:
        write_xlsx(reports, args.output)

    total_hosts = sum(len(r.hosts) for r in reports)
    total_services = sum(len(h.services) for r in reports for h in r.hosts)
    print("[+] Done: {} -> {} ({} hosts, {} services)".format(
        ", ".join(r.basename for r in reports), args.output,
        total_hosts, total_services))


if __name__ == "__main__":
    main()
