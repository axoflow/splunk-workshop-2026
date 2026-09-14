# Cheat sheet

Print this. Nobody should type paths off a slide.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp scripts/env.sh scripts/env.local.sh    # fill in from your table card
source scripts/env.local.sh
echo "$SPLUNK_HOST / index=$SPLUNK_INDEX"
```

## Ingest

```bash
scripts/ingest.py --list                    # what can I send?
scripts/ingest.py --all --dry-run           # show me, send nothing
scripts/ingest.py --all                     # send everything
scripts/ingest.py --case encoded-ps         # just the one that should alert
scripts/ingest.py --case encoded-ps --case dquote   # the Stage 3 pair
scripts/ingest.py --case encoded-ps --no-ta # to a sourcetype with no add-on
```

## Convert

```bash
# Naive. --without-pipeline is REQUIRED on sigma-cli 3.x.
sigma convert -t splunk --without-pipeline rules/execution/powershell_encoded_command.yml

# With your pipeline
sigma convert -t splunk -p ./pipelines/workshop_sysmon.yml \
  rules/execution/powershell_encoded_command.yml

# Compare with the built-in (note the source string!)
sigma convert -t splunk -p sysmon -p splunk_windows \
  rules/execution/powershell_encoded_command.yml

# Data model / tstats instead of raw SPL
sigma convert -t splunk -f data_model -p splunk_cim \
  rules/execution/powershell_encoded_command.yml

sigma list pipelines splunk
sigma list formats splunk
```

## Test

```bash
sigma check rules/          # real: lints the YAML. `sigma test` does NOT exist.

scripts/sigma_test.py --pipeline pipelines/workshop_sysmon.yml \
                      --rules rules/ --tests tests/
```

The harness tests **rule logic**, offline. It cannot know whether a field is
extracted in your Splunk or whether your `source` string is right. **Harness for
logic, Splunk for reality, always both.**

## Investigate

```bash
scripts/query.sh 'EventCode=1 | head 5 | table _time host Image CommandLine'
scripts/query.sh --file /tmp/mapped.spl
EARLIEST=-7d scripts/query.sh '...'
```

## Catch up

```bash
cat solution/NOTES.md
diff -u pipelines/ solution/pipelines/
diff -u collection/splunk-extraction/ solution/collection/splunk-extraction/
cp -r solution/* .
```

---

# The diagnostic checklist

Cheapest first. Each step names the directory to open.

1. **Query returns rows with the detection logic stripped out?**
   No → wrong index/sourcetype/source → `collection/`
2. **Do the fields exist as fields?** (`| table _raw` full, `| table Image` blank)
   No → no extraction, or the data shape changed under a correct parser →
   `collection/`
3. **Fields exist but hold odd values?** (`&amp;`, `-`, empty)
   → encoding, or the source is not populating them → `collection/`
4. **`_time` and `_indextime` far apart?**
   → timestamp parsing failed → `collection/`
5. **Fields populated and correct, still no match?**
   → escaping, wildcards, or a wrong `source` constraint → `pipelines/`
6. **Everything matches, but far too much?**
   → now, finally, `rules/`

## Diagnostic queries

```
| stats count by sourcetype                              did anything arrive?
| stats count by source sourcetype                       what is my source string?
| head 1 | table _raw                                    is the data there?
| head 1 | table Image CommandLine ParentImage           are FIELDS there?
| eval drift=_indextime-_time | table _time _indextime drift    did the timestamp parse?
| metadata type=sourcetypes index=workshop_*             what sourcetypes exist?
| tstats count from datamodel=Endpoint.Processes where index=workshop_* by Processes.process_name
```

---

# The six failures

| # | Symptom | Cause | Layer |
|---|---|---|---|
| 1 | `_raw` full, every field blank | no add-on / TA installed | 1 |
| 2 | fields blank on *some* events only | data re-serialised: `'` became `"` under a correct parser | 1 |
| 3 | events all landed at "now" | same cause: `TIME_PREFIX` no longer matches → index time | 1 |
| 4 | `CommandLine="*&*"` finds nothing | XML entities: field holds `&amp;` | 1 |
| 5 | valid SPL, correct fields, 0 rows | `WinEventLog` vs `XmlWinEventLog` in `source` | 2 |
| 6 | `tstats` empty, raw SPL fine | events not tagged into the data model | 2 |

---

# Traps worth memorising

**XML attribute quotes.** The Windows Event Log writes `Name='Image'`, and the
Splunk TA matches that — **both are correct.** But anything that parses and
re-serialises the XML (Logstash, NXLog, Vector, Cribl, any XML library) emits
`Name="Image"`, and the correct parser then extracts **0 fields instead of 23**.

Your extraction is only correct for the data shape you had when you wrote it.
Make the parser tolerant (`Name=['"]([^'"]+)['"]`) *and* raise a ticket to
normalise upstream — tolerance is deferred maintenance, not a free win.

**Monitor the extraction rate**, because this fails silently:

```
| stats count, count(Image) as extracted
| eval pct=round(100*extracted/count,1) | where pct < 95
```

**XML entities survive extraction.** A command line with `&` is stored as
`&amp;` and your regex extracts it literally. `CommandLine="*& {IEX*"` finds
nothing; `"*&amp; {IEX*"` matches. Decode at ingest if you can. If you decode
with `EVAL`, **decode `&amp;` LAST** — first turns `&amp;lt;` into `<`.

**`WinEventLog:` vs `XmlWinEventLog:`.** Three characters. Records whether
`renderXml=true` was set on the input. The built-in `splunk_windows` pipeline
assumes the former. Check yours with `| stats count by source sourcetype`.

**Splunk boolean precedence is parentheses → `NOT` → `OR` → `AND`.** `OR` binds
*tighter* than `AND`, unlike most languages. That is why generated SPL has no
grouping parens around an OR branch and is still correct:

```
A IN (...) OR B IN (...) C IN (...)     means  (A OR B) AND C
```

Never hand-edit or port generated SPL without this in mind.

**`-f data_model` needs a data-model pipeline.** Otherwise:
`Error: No data model specified by processing pipeline`. One of the few loud
failures — enjoy it.

**Sysmon EID 1 has `Image`. So does EID 5 (process *terminated*).** Without an
`EventCode` constraint your process-creation rule fires on process exits.

**A pipeline is only ever correct relative to one dataset.** That is why layer 2
belongs in your repo, reviewed like code — not inherited from a README.
