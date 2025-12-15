# ------------------------------------------------------------------------
#
# OpenWRT Log Analyzer 
# Version 0.1
# Synoposis: Process the OpenWRT system log file looking for problems.
#            Output two CSV files with results of the analysis.
#
# Python Script created with the use of ChatGPT 
# WARNING: I'm not an OpenWRT expert. The output may contain halucinations
# 
# ------------------------------------------------------------------------


import re
import csv
from collections import defaultdict, Counter

# ---------- CONFIG ----------
LOG_FILE = "system.log"                   # OpenWRT log file
OUI_FILE = "oui.csv"                      # OUI (Organizationally Unique Identifier) MAC identifiers
                                          # https://standards-oui.ieee.org/oui/oui.csv
AUDIT_CSV = "mac_audit_report.csv"
SUMMARY_CSV = "mac_audit_summary.csv"

SECURITY_KEYWORDS = ["fail", "denied", "unauthorized", "error", "intrusion"]
PERF_KEYWORDS = ["timeout", "latency", "drop"]

# ---------- LOAD OUI ----------
oui_map = {}

with open(OUI_FILE, "r", encoding="utf-8", errors="ignore") as f:
    reader = csv.reader(f)
    next(reader)  # skip header
    for row in reader:
        if len(row) >= 3:
            prefix = row[1].strip().upper()  # Assignment column (NO colons)
            vendor = row[2].strip()
            if re.fullmatch(r"[0-9A-F]{6}", prefix):
                oui_map[prefix] = vendor

# ---------- HELPERS ----------
def normalize_mac(mac):
    return ":".join(mac[i:i+2] for i in range(0, 12, 2))

def is_randomized(mac):
    second_nibble = int(mac[1], 16)
    return bool(second_nibble & 2)

def persistence_label(count, span):
    if count == 1:
        return "Transient"
    if span < 50:
        return "Intermittent"
    return "Persistent"

# ---------- PARSE LOG ----------
mac_regex = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")

mac_counts = Counter()
mac_lines = defaultdict(list)
mac_first = {}
mac_last = {}
mac_issues = defaultdict(list)

with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as log:
    for lineno, line in enumerate(log, 1):
        for mac in mac_regex.findall(line):
            raw = mac.replace(":", "").upper()
            mac_fmt = normalize_mac(raw)

            mac_counts[mac_fmt] += 1
            mac_lines[mac_fmt].append(lineno)

            mac_first.setdefault(mac_fmt, lineno)
            mac_last[mac_fmt] = lineno

            lower = line.lower()
            for kw in SECURITY_KEYWORDS + PERF_KEYWORDS:
                if kw in lower:
                    mac_issues[mac_fmt].append(f"{kw}@{lineno}")

# ---------- ANALYSIS ----------
audit_rows = []
vendor_counts = Counter()
suspicious = set()

for mac, count in mac_counts.items():
    raw = mac.replace(":", "")
    prefix = raw[:6]
    vendor = oui_map.get(prefix, "Unknown Vendor")
    vendor_counts[vendor] += count

    randomized = is_randomized(raw)
    mac_type = "Randomized" if randomized else "Globally Assigned"

    first = mac_first[mac]
    last = mac_last[mac]
    span = last - first
    persistence = persistence_label(count, span)

    issues = "; ".join(mac_issues.get(mac, []))

    flags = []

    if vendor == "Unknown Vendor" and not randomized:
        flags.append("Unknown Vendor")

    if issues:
        flags.append("Issues Detected")

    # SUSPICIOUS LOGIC (FIXED)
    is_suspicious = (
        not randomized
        and vendor == "Unknown Vendor"
        and (persistence == "Transient" or issues)
    )

    if is_suspicious:
        suspicious.add(mac)

    audit_rows.append([
        mac,
        vendor,
        mac_type,
        count,
        first,
        last,
        span,
        persistence,
        issues,
        "; ".join(flags),
        "YES" if is_suspicious else "NO"
    ])

# ---------- WRITE AUDIT CSV ----------
with open(AUDIT_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow([
        "MAC Address", "Vendor", "MAC Type", "Occurrences",
        "First Seen", "Last Seen", "Span",
        "Persistence", "Issues", "Audit Flags", "Suspicious"
    ])
    writer.writerows(audit_rows)

# ---------- WRITE SUMMARY ----------
with open(SUMMARY_CSV, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)

    writer.writerow(["Total Unique MACs", len(mac_counts)])
    writer.writerow(["Suspicious MACs", len(suspicious)])
    writer.writerow([])

    writer.writerow(["Top Vendors"])
    writer.writerow(["Vendor", "Count"])
    for v, c in vendor_counts.most_common(20):
        writer.writerow([v, c])

    writer.writerow([])
    writer.writerow(["Suspicious MAC Addresses"])
    for mac in sorted(suspicious):
        writer.writerow([mac])

print("Audit complete.")
print(f"- {AUDIT_CSV}")
print(f"- {SUMMARY_CSV}")
