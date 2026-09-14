#!/usr/bin/env python3
"""Ingest the workshop's sample Windows events into Splunk.

Quick start
-----------

    scripts/ingest.py --list                 # what can I send?
    scripts/ingest.py --dry-run              # show me, don't send
    scripts/ingest.py --case encoded-ps      # send the one that should alert
    scripts/ingest.py --all                  # send everything

Every case is a real Sysmon Event ID 1 in `collection/*.xml`. Apart from the
timestamps, nothing is reformatted on the way out -- in particular the QUOTE
STYLE of the XML attributes is preserved exactly, because half this workshop is
about what one quote character does to a detection.

Timestamps are the exception
---------------------------

The samples were captured in April 2024 and Splunk takes _time from the event
body, so sending them as-is buries them two years back and `earliest=-15m`
finds nothing. By default this script shifts every event forward so the newest
lands at send time, keeping the eleven minutes of spacing between them.

    scripts/ingest.py --all                  # timestamps shifted to now
    scripts/ingest.py --all --original-time  # 2024, as captured

Use --original-time when you want to demonstrate index-time fallback: with the
captured stamps, the three single-quoted samples parse to 2024 and the
double-quoted one defeats props.conf's TIME_PREFIX, silently lands at "now",
and is the only one a recent search returns.

Why a script and not a curl one-liner
-------------------------------------

Three things are easy to get wrong by hand, and all three produce a
*successful* HTTP 200 with unusable data:

  * Raw XML must go to /services/collector/raw, not /event. The /event
    endpoint expects JSON, and posting XML to it stores your event as a
    quoted string.
  * Metadata (index, sourcetype, source, host) travels as query parameters on
    the raw endpoint, not in the body.
  * A multi-line XML document needs the sourcetype's LINE_BREAKER to agree
    with it, or Splunk splits one event into fourteen.

--sourcetype is the interesting knob
------------------------------------

    scripts/ingest.py --case encoded-ps                     # sourcetype with a TA
    scripts/ingest.py --case encoded-ps --no-ta             # sourcetype with nothing

The second one is not a mistake. Sending the identical bytes to a sourcetype
no add-on knows about is Stage 2 of the lab: the event indexes fine, is fully
searchable as text, and has no fields at all. Every Sigma rule you convert
assumes fields that only exist because somebody installed an add-on.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COLLECTION = REPO / "collection"

# Sourcetype that a Sysmon add-on claims. Field extraction happens.
SOURCETYPE_TA = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
# Sourcetype nothing claims. Indexes fine, extracts nothing. Stage 2.
SOURCETYPE_NO_TA = "workshop:sysmon_raw"

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


@dataclass(frozen=True)
class Case:
    name: str
    filename: str
    should_alert: bool
    summary: str
    teaches: str

    @property
    def path(self) -> Path:
        return COLLECTION / self.filename


CASES: tuple[Case, ...] = (
    Case(
        name="encoded-ps",
        filename="sysmon-eid1-encoded-ps.xml",
        should_alert=True,
        summary="powershell.exe -enc <base64>, parent cmd.exe",
        teaches="The event the detection is supposed to catch. If this does "
                "not alert, something in the chain is broken -- that is the lab.",
    ),
    Case(
        name="dquote",
        filename="sysmon-eid1-encoded-ps-dquote.xml",
        should_alert=True,
        summary="the SAME event, XML attributes double-quoted instead of single",
        teaches="Identical content, one normalising hop upstream. The Splunk "
                "TA extracts from single-quoted XML because that is what Windows "
                "emits -- it is correct, and it gets 0 of 23 fields from this. "
                "Ingest it next to 'encoded-ps' and compare.",
    ),
    Case(
        name="quotes",
        filename="sysmon-eid1-quotes.xml",
        should_alert=True,
        summary="encoded PowerShell whose command line contains \" ' & > ",
        teaches="XML escaping, Splunk field extraction, and SPL quoting each "
                "handle these differently. Should alert. Frequently does not.",
    ),
    Case(
        name="benign",
        filename="sysmon-eid1-benign.xml",
        should_alert=False,
        summary="WmiPrvSE.exe -secured -Embedding, parent svchost.exe",
        teaches="Must NOT alert. Proves your query is selective rather than "
                "matching every process on the host.",
    ),
)

BY_NAME = {c.name: c for c in CASES}


# --------------------------------------------------------------------------
# Retiming
# --------------------------------------------------------------------------
# The samples are real captures, so they carry the timestamp they were captured
# at -- April 2024. Splunk takes _time from the event body, not from when it
# arrived, so sending them verbatim buries them two years deep and a search over
# "last 15 minutes" finds nothing. Worse, it finds ALMOST nothing: the
# double-quoted sample defeats the TIME_PREFIX in props.conf, silently falls
# back to index time, and is the only one that shows up. One event out of four,
# and it is the broken one.
#
# So by default we shift every event forward to now. Two rules:
#
#   * The QUOTE CHARACTER is preserved exactly. Stage 3 rests on the two
#     encoded-ps samples differing by one character; retiming must not be that
#     character.
#   * RELATIVE SPACING is preserved. The corpus spans about eleven minutes and
#     the events are ordered; flattening them all onto the same instant would
#     throw that away. The newest event lands at send time and the rest keep
#     their original distance behind it.
#
# --original-time turns this off and sends the 2024 timestamps as captured,
# which is what you want when demonstrating index-time fallback drift.

# Group 2 is the quote character; the backreference forces the closing quote to
# match the opening one, so a single-quoted attribute stays single-quoted.
RE_SYSTEM_TIME = re.compile(r"(<TimeCreated\s+SystemTime=)(['\"])(.*?)\2")
RE_UTC_TIME = re.compile(r"(<Data\s+Name=(['\"])UtcTime\2\s*>)([^<]*)")


# Splits a stamp into date-time, fractional digits and whatever trails it, so a
# replacement can be built with the SAME SHAPE. The samples carry nine
# fractional digits and a Z; EventData/UtcTime carries three and nothing. Emit a
# different width and the event changes length, which would break the "identical
# apart from one character" comparison Stage 3 is built on.
RE_STAMP_SHAPE = re.compile(r"^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)\.(\d+)(.*)$")


def parse_system_time(text: str) -> datetime:
    """Parse a Sysmon UTC stamp, whatever its fractional width.

    strptime's %f tops out at 6 digits and the samples carry 9, so the tail is
    truncated. That costs sub-microsecond precision and nothing that matters.
    """
    match = RE_STAMP_SHAPE.match(text.strip())
    if not match:
        raise SystemExit(f"error: cannot parse timestamp {text!r}")
    return datetime.strptime(
        f"{match.group(1)}.{match.group(2)[:6]:<06s}".replace(" ", "T"),
        "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=timezone.utc)


def fmt_like(when: datetime, template: str) -> str:
    """Render `when` with the same separator, fractional width and suffix as
    `template`, so the replacement is the same number of bytes."""
    match = RE_STAMP_SHAPE.match(template.strip())
    if not match:
        raise SystemExit(f"error: cannot parse timestamp {template!r}")
    sep = "T" if "T" in match.group(1) else " "
    width = len(match.group(2))
    frac = (f"{when.microsecond:06d}" + "0" * width)[:width]
    return f"{when:%Y-%m-%d}{sep}{when:%H:%M:%S}.{frac}{match.group(3)}"


def corpus_latest() -> datetime:
    """Newest SystemTime across every sample, so the shift is the same however
    many cases you select. Sending one case puts it at the same distance behind
    now as it would be if you had sent all four."""
    times = []
    for case in CASES:
        if not case.path.is_file():
            continue
        match = RE_SYSTEM_TIME.search(case.path.read_text(encoding="utf-8"))
        if match:
            times.append(parse_system_time(match.group(3)))
    if not times:
        raise SystemExit(
            "error: no <TimeCreated SystemTime=...> found in any sample.\n"
            "       Cannot compute the retiming offset. Use --original-time.")
    return max(times)


def retime(xml: str, offset: timedelta, case_name: str) -> tuple[str, datetime]:
    """Shift SystemTime and UtcTime forward by offset, preserving quote style.

    Returns the rewritten XML and the new event time. Raises if SystemTime is
    absent -- a sample we cannot retime would land in 2024 while its siblings
    land at now, which is exactly the kind of silent half-failure this whole
    workshop is about.
    """
    match = RE_SYSTEM_TIME.search(xml)
    if not match:
        raise SystemExit(
            f"error: {case_name}: no <TimeCreated SystemTime=...> to retime.\n"
            "       Use --original-time to send the sample untouched.")

    when = parse_system_time(match.group(3)) + offset

    xml = RE_SYSTEM_TIME.sub(
        lambda m: f"{m.group(1)}{m.group(2)}"
                  f"{fmt_like(when, m.group(3))}{m.group(2)}",
        xml, count=1)

    # UtcTime is Sysmon's own copy of the same instant, inside EventData. Leaving
    # it at 2024 would put the event body at odds with _time -- and the lab spends
    # twenty minutes teaching people to trust the event body.
    xml = RE_UTC_TIME.sub(
        lambda m: f"{m.group(1)}{fmt_like(when, m.group(3))}", xml, count=1)

    return xml, when


# --------------------------------------------------------------------------
# Reading and shaping
# --------------------------------------------------------------------------

def read_event(case: Case, *, one_line: bool,
               offset: timedelta | None) -> tuple[str, datetime | None]:
    """Return the XML to send, and the event time it carries.

    one_line collapses the document onto a single line. That removes any
    dependency on the sourcetype's LINE_BREAKER, which is one fewer variable
    while you are trying to work out why a field is missing. It changes
    nothing about the data: XML does not care about whitespace between tags.

    offset shifts the event's timestamps forward; None sends them as captured
    and the returned time is None. See the retiming section above.
    """
    if not case.path.is_file():
        raise SystemExit(f"error: missing sample: {case.path}")

    xml = case.path.read_text(encoding="utf-8")

    # Fail loudly here rather than letting Splunk index something malformed.
    try:
        ET.fromstring(xml)
    except ET.ParseError as exc:
        raise SystemExit(f"error: {case.path.name} is not well-formed XML: {exc}")

    # Strip XML comments. They are provenance notes for whoever reads the repo;
    # Splunk should receive the event, not the annotation. Doing this keeps the
    # single- and double-quoted samples the same size, which matters because
    # Stage 3 rests on them being identical apart from the quote character.
    xml = re.sub(r"<!--.*?-->", "", xml, flags=re.S)

    when = None
    if offset is not None:
        xml, when = retime(xml, offset, case.name)

    if one_line:
        xml = re.sub(r">\s+<", "><", xml.strip())
        xml = re.sub(r"\s*\n\s*", " ", xml)

    # Retiming must not have disturbed the document.
    try:
        ET.fromstring(xml)
    except ET.ParseError as exc:
        raise SystemExit(f"error: {case.path.name} became malformed after "
                         f"retiming: {exc}")

    return xml.strip(), when


def describe(case: Case) -> dict[str, str]:
    """Pull the handful of fields the lab talks about, for --dry-run output."""
    root = ET.fromstring(case.path.read_text(encoding="utf-8"))
    data = {d.get("Name"): (d.text or "") for d in root.findall("e:EventData/e:Data", NS)}
    system = root.find("e:System", NS)
    return {
        "EventID": system.find("e:EventID", NS).text,
        "Computer": system.find("e:Computer", NS).text,
        "UtcTime": data.get("UtcTime", ""),
        "Image": data.get("Image", ""),
        "CommandLine": data.get("CommandLine", ""),
        "ParentImage": data.get("ParentImage", ""),
        "User": data.get("User", ""),
    }


# --------------------------------------------------------------------------
# Sending
# --------------------------------------------------------------------------

def hec_url(host: str, port: str, *, index: str, sourcetype: str,
            source: str, hostname: str) -> str:
    """Raw endpoint + metadata as query params.

    /services/collector/raw takes the body as-is. /services/collector/event
    expects JSON and would store this XML as a string -- a 200 response and
    unusable data, which is the worst combination.
    """
    params = urllib.parse.urlencode({
        "index": index,
        "sourcetype": sourcetype,
        "source": source,
        "host": hostname,
    })
    return f"https://{host}:{port}/services/collector/raw?{params}"


def send(url: str, token: str, body: str, *, insecure: bool) -> tuple[bool, str]:
    try:
        import requests
        import urllib3
    except ImportError:
        raise SystemExit(
            "error: requests is not installed.\n"
            "       pip install -r requirements.txt   (or use --dry-run)"
        )
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.post(
            url,
            headers={"Authorization": f"Splunk {token}"},
            data=body.encode("utf-8"),
            verify=not insecure,
            timeout=30,
        )
    except requests.exceptions.SSLError:
        return False, ("TLS verification failed. The sandbox uses a self-signed "
                       "certificate -- this script passes -k by default, so if you "
                       "see this you have passed --secure.")
    except requests.exceptions.ConnectionError as exc:
        return False, (f"could not connect: {exc}\n"
                       "       Is HEC enabled, and is the port right? Default is 8088.")

    ok = response.status_code == 200 and '"code":0' in response.text.replace(" ", "")
    return ok, f"HTTP {response.status_code} {response.text.strip()}"


HEC_ERRORS = {
    "1": "token disabled",
    "2": "token is required -- the Authorization header did not arrive",
    "3": "invalid request body",
    "4": "invalid token -- check it against your table card",
    "5": "no data -- the body was empty",
    "6": "invalid data format",
    "7": "incorrect index, or the token is not allowed to write to it",
    "8": "internal server error",
    "9": "server is busy",
    "10": "data channel is missing",
    "11": "invalid data channel",
    "12": "event field is required",
    "13": "event field cannot be blank",
    "14": "ACK is disabled",
}


def explain_hec(message: str) -> str | None:
    match = re.search(r'"code"\s*:\s*(\d+)', message)
    if not match or match.group(1) == "0":
        return None
    return HEC_ERRORS.get(match.group(1))


# --------------------------------------------------------------------------

def verification_spl(index: str, sourcetype: str, no_ta: bool) -> str:
    lines = [
        "Now go and look. In Splunk, run these in order:",
        "",
        f"  1. Did anything arrive at all?",
        f"     index={index} earliest=-15m | stats count by sourcetype",
        "",
        f"  2. What does the raw event look like?",
        f'     index={index} sourcetype="{sourcetype}" earliest=-15m | head 1 | table _raw',
        "",
        f"  3. Do FIELDS exist? (this is the interesting one)",
        f'     index={index} sourcetype="{sourcetype}" earliest=-15m | head 1'
        f" | table Image CommandLine ParentImage User",
    ]
    if no_ta:
        lines += [
            "",
            "  You sent to a sourcetype no add-on claims, so expect step 3 to be",
            "  empty while steps 1 and 2 look perfectly healthy. That gap is",
            "  Stage 2 of the lab -- your rule is about to query fields that do",
            "  not exist.",
        ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest the workshop's sample Windows events into Splunk.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Configuration comes from the environment; see scripts/env.sh.",
    )
    parser.add_argument("--case", action="append", metavar="NAME",
                        help="case to send; repeatable. See --list.")
    parser.add_argument("--all", action="store_true", help="send every case")
    parser.add_argument("--list", action="store_true", help="list cases and exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be sent; send nothing, need no token")
    parser.add_argument("--no-ta", action="store_true",
                        help=f"send to '{SOURCETYPE_NO_TA}', which no add-on claims")
    parser.add_argument("--sourcetype", help="override the sourcetype entirely")
    parser.add_argument("--index", default=None, help="override SPLUNK_INDEX")
    parser.add_argument("--multiline", action="store_true",
                        help="send the XML as-is instead of collapsing to one line")
    parser.add_argument("--original-time", action="store_true",
                        help="send the captured 2024 timestamps instead of "
                             "shifting them to now (for the index-time drift demo)")
    parser.add_argument("--secure", action="store_true",
                        help="verify TLS (the sandbox cert is self-signed, so this fails)")
    args = parser.parse_args()

    if args.list:
        print("Available cases:\n")
        for c in CASES:
            flag = "should ALERT" if c.should_alert else "must NOT alert"
            print(f"  {c.name:<12} {flag}")
            print(f"  {'':<12} {c.summary}")
            print(f"  {'':<12} {c.teaches}")
            print(f"  {'':<12} file: collection/{c.filename}")
            print()
        print("Send one with:   scripts/ingest.py --case encoded-ps")
        print("Send the pair:   scripts/ingest.py --case encoded-ps --case dquote")
        print()
        print("That pair is Stage 3: identical event content, identical extraction")
        print("config, and only one of them produces fields. Compare with:")
        print("  index=<yours> earliest=-15m")
        print("  | stats count, count(Image) as extracted by source")
        return 0

    if args.all:
        selected = list(CASES)
    elif args.case:
        selected = []
        for name in args.case:
            if name not in BY_NAME:
                return fail(f"unknown case {name!r}. Try --list.")
            selected.append(BY_NAME[name])
    else:
        return fail("nothing selected. Use --case NAME, --all, or --list.")

    index = args.index or os.environ.get("SPLUNK_INDEX") or "workshop_00"
    sourcetype = args.sourcetype or (SOURCETYPE_NO_TA if args.no_ta else SOURCETYPE_TA)
    splunk_host = os.environ.get("SPLUNK_HOST", "your-instance.workshop.local")
    hec_port = os.environ.get("SPLUNK_HEC_PORT", "8088")
    token = os.environ.get("SPLUNK_HEC_TOKEN", "")

    # Anchor the newest sample at send time; everything else keeps its distance.
    offset = None if args.original_time else (
        datetime.now(timezone.utc) - corpus_latest())

    print(f"index      : {index}")
    print(f"sourcetype : {sourcetype}"
          + ("   <-- no add-on claims this" if sourcetype == SOURCETYPE_NO_TA else ""))
    print(f"endpoint   : https://{splunk_host}:{hec_port}/services/collector/raw")
    print(f"cases      : {', '.join(c.name for c in selected)}")
    if offset is None:
        print("timestamps : AS CAPTURED (2024-04-28) -- searches over recent")
        print("             windows will not find these. Drop --original-time")
        print("             to shift them to now.")
    else:
        print(f"timestamps : shifted forward {offset.days} days to now")
    print()

    if not args.dry_run and not token:
        return fail("SPLUNK_HEC_TOKEN is not set.\n"
                    "       Copy scripts/env.sh to scripts/env.local.sh and fill it in,\n"
                    "       export it, or use --dry-run to preview without sending.")

    sent = failed = 0
    for case in selected:
        body, when = read_event(case, one_line=not args.multiline, offset=offset)
        fields = describe(case)
        flag = "should ALERT" if case.should_alert else "must NOT alert"

        print(f"[{case.name}] {flag}")
        print(f"    Image       : {fields['Image']}")
        print(f"    CommandLine : {fields['CommandLine'][:96]}"
              + ("..." if len(fields["CommandLine"]) > 96 else ""))
        print(f"    ParentImage : {fields['ParentImage']}")
        if when is not None:
            print(f"    event time  : {when:%Y-%m-%d %H:%M:%S} UTC"
                  f"   (was {fields['UtcTime']} UTC)")
        else:
            print(f"    event time  : {fields['UtcTime']} UTC   (as captured)")
        print(f"    bytes       : {len(body.encode('utf-8'))}"
              + ("  (single line)" if not args.multiline else "  (as-is, multi-line)"))

        if args.dry_run:
            print(f"    [dry-run] not sent")
            print()
            continue

        url = hec_url(splunk_host, hec_port, index=index, sourcetype=sourcetype,
                      source=sourcetype, hostname=fields["Computer"])
        ok, message = send(url, token, body, insecure=not args.secure)
        if ok:
            print(f"    sent        : {message}")
            sent += 1
        else:
            print(f"    FAILED      : {message}")
            hint = explain_hec(message)
            if hint:
                print(f"    hint        : {hint}")
            failed += 1
        print()

    if args.dry_run:
        print("Dry run. Nothing was sent. Drop --dry-run to send for real.")
        return 0

    print(f"{sent} sent, {failed} failed.")
    if failed:
        return 1

    print()
    print(verification_spl(index, sourcetype, args.no_ta))
    print()
    print("Indexing takes a second or two. If a search comes back empty, wait and retry")
    print("before you start debugging.")
    return 0


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
