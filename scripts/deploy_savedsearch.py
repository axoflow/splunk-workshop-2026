#!/usr/bin/env python3
"""Deploy generated SPL to Splunk as a saved search. This is what CI runs.

    scripts/deploy_savedsearch.py --spl /tmp/mapped.spl --name "T1059.001 Encoded PS"
    scripts/deploy_savedsearch.py --spl /tmp/mapped.spl --name "..." --dry-run
    scripts/deploy_savedsearch.py --manifest deploy-manifest.json --spl-dir out/

Configuration comes from the same environment variables as the shell scripts
(see scripts/env.sh): SPLUNK_HOST, SPLUNK_API_PORT, SPLUNK_USER,
SPLUNK_PASSWORD, SPLUNK_INDEX.

--manifest writes a deployment record: rule id, saved-search name, and a
SHA-256 of the deployed SPL. That record is what makes a rollback mean
something -- "restore the detections that were live at 09:00" is only
answerable if you wrote down what was live at 09:00.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

DEFAULTS = {
    "SPLUNK_HOST": "your-instance.workshop.local",
    "SPLUNK_API_PORT": "8089",
    "SPLUNK_USER": "workshop",
    "SPLUNK_INDEX": "workshop_00",
}


def env(name: str) -> str:
    return os.environ.get(name) or DEFAULTS.get(name, "")


def api_base() -> str:
    return f"https://{env('SPLUNK_HOST')}:{env('SPLUNK_API_PORT')}"


def deploy(session, name: str, spl: str, *,
           cron: str, earliest: str, latest: str, disabled: bool,
           dry_run: bool) -> dict:
    """Create or update one saved search.

    Splunk has no upsert on this endpoint: POST to the collection creates and
    409s if the name exists, POST to the entity updates. Try create, fall
    back to update -- and note that on update you must NOT resend `name`.
    """
    body = {
        "search": spl,
        "cron_schedule": cron,
        "dispatch.earliest_time": earliest,
        "dispatch.latest_time": latest,
        "is_scheduled": "0" if disabled else "1",
        "disabled": "1" if disabled else "0",
        "output_mode": "json",
    }

    if dry_run:
        print(f"[dry-run] would deploy saved search {name!r}")
        print(f"[dry-run]   cron={cron} earliest={earliest} latest={latest} "
              f"scheduled={not disabled}")
        for line in spl.splitlines():
            print(f"[dry-run]   | {line}")
        return {"name": name, "action": "dry-run"}

    collection = f"{api_base()}/servicesNS/nobody/search/saved/searches"
    response = session.post(collection, data={**body, "name": name})

    if response.status_code == 409:
        # safe='' so a name containing / is encoded rather than becoming a
        # path segment and 404ing.
        entity = f"{collection}/{quote(name, safe='')}"
        response = session.post(entity, data=body)
        action = "updated"
    else:
        action = "created"

    if not response.ok:
        raise SystemExit(
            f"error: deploying {name!r} failed with HTTP {response.status_code}\n"
            f"{response.text[:2000]}"
        )

    print(f"{action} saved search {name!r}")
    return {"name": name, "action": action}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--spl", help="file containing the SPL to deploy")
    parser.add_argument("--name", help="saved search name")
    parser.add_argument("--spl-dir", help="deploy every *.spl in this directory; "
                                          "the filename stem becomes the search name")
    parser.add_argument("--cron", default="*/10 * * * *",
                        help="cron schedule (default: every 10 minutes)")
    parser.add_argument("--earliest", default="-15m")
    parser.add_argument("--latest", default="now")
    parser.add_argument("--disabled", action="store_true",
                        help="deploy but leave unscheduled -- how you stage a new rule")
    parser.add_argument("--dry-run", action="store_true",
                        help="print what would be deployed and exit; needs no credentials")
    parser.add_argument("--manifest", help="write a deployment manifest to this path")
    parser.add_argument("--insecure", action="store_true", default=True,
                        help="accept the sandbox self-signed certificate (default)")
    args = parser.parse_args()

    targets: list[tuple[str, str]] = []
    if args.spl_dir:
        directory = Path(args.spl_dir)
        if not directory.is_dir():
            return _fail(f"no such directory: {directory}")
        for path in sorted(directory.glob("*.spl")):
            targets.append((path.stem, path.read_text().strip()))
        if not targets:
            return _fail(f"no .spl files in {directory}")
    elif args.spl:
        if not args.name:
            return _fail("--spl requires --name")
        path = Path(args.spl)
        if not path.is_file():
            return _fail(f"no such file: {path}")
        spl = path.read_text().strip()
        if not spl:
            return _fail(f"{path} is empty -- did the conversion actually produce output?")
        targets.append((args.name, spl))
    else:
        return _fail("give either --spl with --name, or --spl-dir")

    session = None
    if not args.dry_run:
        # Imported here rather than at module scope so --dry-run runs on a bare
        # Python with nothing installed. That is the path CI uses to preview a
        # deployment on a PR, where there are no Splunk credentials to use.
        try:
            import requests
            import urllib3
        except ImportError:
            return _fail("requests is not installed. pip install -r requirements.txt, "
                         "or use --dry-run.")

        password = os.environ.get("SPLUNK_PASSWORD")
        if not password:
            return _fail("SPLUNK_PASSWORD is not set. Use --dry-run to preview without it.")

        session = requests.Session()
        session.auth = (env("SPLUNK_USER"), password)
        session.verify = not args.insecure
        if args.insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    records = []
    for name, spl in targets:
        record = deploy(session, name, spl,
                        cron=args.cron, earliest=args.earliest, latest=args.latest,
                        disabled=args.disabled, dry_run=args.dry_run)
        record["spl_sha256"] = hashlib.sha256(spl.encode()).hexdigest()
        records.append(record)

    if args.manifest:
        manifest = {
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "target": api_base(),
            "index": env("SPLUNK_INDEX"),
            "searches": records,
        }
        Path(args.manifest).write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"wrote manifest to {args.manifest}")

    return 0


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
