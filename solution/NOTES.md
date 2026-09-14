# Solutions — every stage, with the reasoning

The rule is never edited. Not once, in any stage. Diff it and see:

```bash
diff -u rules/ solution/rules/          # no output
```

---

## Stage 1 — Green but dead

Nothing to fix yet. The point of the stage is the experience: a syntactically
perfect query, running cleanly, over an index that definitely contains the
matching event, returning nothing.

The instinct this is meant to break is "the rule must be wrong". The rule
matched the event when you read them side by side. It still does. The problem is
in the space between them, and that space has six things in it.

---

## Stage 2 — No add-on, no fields

**Nothing to fix in this repo** — the fix is installing
`Splunk_TA_microsoft_sysmon`, which is a sandbox-level action.

**What to take away:** Splunk stores text. Fields are a *search-time
interpretation* of that text, produced by configuration somebody has to install.
`| table _raw` working while `| table Image` is blank is not a contradiction and
not an error — it is the normal behaviour of a schema-on-read system being asked
for a field nobody defined.

Every Sigma rule you will ever convert is a pile of field references. Sigma has
never seen your data and cannot know whether those fields exist.

Three ways to get fields, and when each is right:

| Approach | Use it when |
|---|---|
| Install the TA | Production. Always the answer if you can get it. |
| `spath` at search time | A one-off hunt. Correct, and too slow to schedule. |
| Custom `props`/`transforms` | No TA exists, or it does not claim your sourcetype. |

The `spath` result is worth understanding rather than skipping: it *does* parse
the XML, and it gives you `Event.EventData.Data{@Name}` and
`Event.EventData.Data` as parallel multivalue fields. Structure, faithfully
preserved — and still no field called `Image`. Getting from there to flat fields
needs `mvzip` / `mvexpand` / `eval {k}=v`, on every search, forever. That is why
extraction belongs at layer 1.

---

## Stage 3 — Same event, different producer

**The starter config was not broken.** It matched single-quoted XML attributes,
exactly like `Splunk_TA_microsoft_sysmon`, because that is what the Windows
Event Log emits. Measured against `collection/sysmon-eid1-encoded-ps.xml`: 23 of
23 fields.

It extracted **0 of 23** from `collection/sysmon-eid1-encoded-ps-dquote.xml` —
the same event, same 23 field values, 2038 bytes each, differing by nothing but
the quote character around attribute names.

```bash
diff -u collection/splunk-extraction/ solution/collection/splunk-extraction/
```

### Where the double-quoted event comes from

XML permits `'` and `"` interchangeably and expresses no preference. Windows
writes single. **Anything that parses and re-serialises writes double** — that
is the default in essentially every XML library:

```bash
python3 -c "import xml.etree.ElementTree as ET; \
  ET.register_namespace('','http://schemas.microsoft.com/win/2004/08/events/event'); \
  print(ET.tostring(ET.parse('collection/sysmon-eid1-encoded-ps.xml').getroot(), encoding='unicode'))" \
  | head -3
```

So the second file is your event after **one normalising hop**: a Logstash
filter, an NXLog transform, a Vector remap, a Cribl pipeline, a Python enricher,
a vendor appliance. Added for a reason unrelated to detection, probably without
telling anyone who owns detections.

Nobody made a mistake:

- Windows is correct. Single quotes are valid XML.
- The normalising hop is correct. Double quotes are valid XML, and every byte of
  data was preserved.
- The TA is correct. It parses what Windows emits.
- **Your detections are dead.**

> An extraction config is not "correct" in the abstract. It is correct *for the
> shape of the data you had when you wrote it.* That shape changes upstream,
> silently, and nothing in Splunk will tell you.

### The timestamp — one character, second casualty

```diff
-TIME_PREFIX = <TimeCreated SystemTime='
+TIME_PREFIX = <TimeCreated SystemTime=
 MAX_TIMESTAMP_LOOKAHEAD = 45
```

`TIME_PREFIX` is a literal string, not a regex, so it cannot be made tolerant
the way the extraction regex can. Dropping the quote and letting
`MAX_TIMESTAMP_LOOKAHEAD` skip over it works for both styles.

The failure mode is worse than missing fields, because missing fields are
visible the moment you look. Splunk silently falls back to **index time**:
searches work, dashboards populate, nothing is empty. Weeks later an incident
timeline does not line up.

```
| eval drift=_indextime-_time | table _time _indextime drift source
```

Seconds means it parsed. Months means it did not.

### The two fixes, and the trade-off

**Option A — tolerant parser.** `Name=['"]([^'"]+)['"]`. Measured: 23 fields
from both. *Costs:* you now own a fork of the TA's logic. When the TA updates,
yours does not; in two years someone finds two definitions and has to work out
which is live. **Tolerance is deferred maintenance, not a free win.**

**Option B — normalise at the source, keep the parser strict.** The TA stays
stock and every other consumer is fixed too. *Costs:* you probably do not own
that hop.

**Do both, in order:** A today so detections work, B as a ticket so the fork can
be removed. What you must not do is A silently — no comment, no ticket — because
then the fork is permanent and nobody remembers why.

### The part that outlives the workshop

If extraction depends on the shape of incoming data, a change in that shape is
an outage nobody reports. Monitor it:

```
index=... sourcetype=workshop:sysmon_raw earliest=-1h
| stats count, count(Image) as extracted
| eval pct=round(100*extracted/count, 1)
| where pct < 95
```

Catches this failure, a TA upgrade that renames fields, and a producer changing
its output format. All silent today.

### XML entities — the one no regex fix solves

Extracted values are still XML-encoded. A command line containing `&` holds the
literal five characters `&amp;`:

```
CommandLine="*& {IEX*"        -> no results
CommandLine="*&amp; {IEX*"    -> matches
```

Your detection searches the decoded string; your index holds the encoded one.
Command lines contain `&` and `>` constantly, so this hits real rules.

Fix at ingest if you can. At search time, the `EVAL` is in
`solution/collection/splunk-extraction/props.conf`, and **`&amp;` decodes LAST.**
Verified:

| stored | `&amp;` first | `&amp;` last |
|---|---|---|
| `echo &amp;lt;div&amp;gt;` | `echo <div>` ❌ | `echo &lt;div&gt;` ✅ |

Decoding `&amp;` first turns an escaped literal into a real character — a
double-decode bug, the class of mistake that earns XML parsers CVEs.

### Why the offline harness is silent through all of this

`scripts/sigma_test.py` passes before and after Stage 3. It cannot fail here: it
evaluates rule logic against JSON samples, and extraction is a property of your
Splunk, not of the rule.

**This entire stage is invisible to your test suite.** Not a flaw in the
harness — the boundary of what any offline test can know.

---

## Stage 4 — The source constraint

```diff
-transformations: []
+transformations:
+  - id: sysmon_process_creation
+    type: add_condition
+    conditions:
+      EventCode: 1
+      source: 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'
+    rule_conditions:
+      - type: logsource
+        category: process_creation
+        product: windows
```

### Why the pipeline looked unnecessary

Sysmon EID 1 field names **already match Sigma's**: `Image` is `Image`,
`CommandLine` is `CommandLine`, `ParentImage` is `ParentImage`. Sigma's
`process_creation` taxonomy was largely modelled on Sysmon.

So there is no renaming to do, and it is easy to conclude no pipeline is needed.
What that costs you is every constraint: no index, no sourcetype, no event ID. A
query that searches everything you can read for anything with an `Image` field —
which includes Sysmon **Event ID 5, process *terminated***. Your process-creation
detection now fires when processes exit.

### The three characters

The official pipeline:

```bash
sigma convert -t splunk -p sysmon -p splunk_windows rules/execution/powershell_encoded_command.yml
# source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
```

Ours:

```
source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
```

`Xml`. That prefix records whether events were XML-rendered on the way in
(`renderXml=true` in `inputs.conf`) or arrived as pre-formatted message text.
Both are normal. Which you have was decided by whoever built your forwarders,
possibly years ago, for reasons unrelated to detection.

Point the built-in pipeline at XML-rendered data and **every rule converts
cleanly, deploys cleanly, and matches nothing.**

This is why the lab makes you run `| stats count by source sourcetype` instead of
trusting a default. **A pipeline is only ever correct relative to one dataset**,
and that is the argument for keeping layer 2 in your repo, reviewed like code.

### Why the offline harness passes even before this fix

Run it against the starter pipeline and it passes. That is not a bug in the
harness — it is the boundary of what any offline test can know.

`scripts/sigma_test.py` evaluates the rule's detection logic against JSON
samples. It can prove the *logic* is right. It cannot know that `Image` is not an
extracted field in your Splunk, or that your `source` string has an `Xml` prefix.
Those are properties of an environment, not of a rule.

**So: harness for logic, Splunk for reality, always both.** The harness's own
docstring says exactly this. A green test suite and a dead detection coexist very
comfortably.

---

## Stage 5 — SPL is not the only query

Nothing to fix; the stage is a comparison.

```bash
sigma convert -t splunk -f data_model -p splunk_cim rules/execution/powershell_encoded_command.yml
```

| Sigma | Raw SPL | Data model |
|---|---|---|
| `Image` | `Image` | `Processes.process_path` |
| `CommandLine` | `CommandLine` | `Processes.process` |
| `OriginalFileName` | `OriginalFileName` | `Processes.original_file_name` |
| `ParentImage` | `ParentImage` | `Processes.parent_process_path` |

One rule, two queries, no shared field names. Testing one tells you nothing about
the other.

**The format and the pipeline are coupled**, and unusually for this workshop, it
says so:

```
Error: Error while converting: No data model specified by processing pipeline
```

A hard error. Compare how much easier that was to diagnose than the five silent
failures preceding it — that contrast is the argument for building loud failures
into your own tooling wherever you can.

**`tstats` needs three things a correct query cannot supply:** the CIM add-on
installed, your events tagged into the data model (which needs the TA from Stage
2 — no TA, no tags, empty model), and acceleration enabled, or
`summariesonly=false` doing the slow raw search you were trying to avoid.

Check:

```
| tstats count from datamodel=Endpoint.Processes where index=workshop_* by Processes.process_name
```

Empty here while raw SPL returns events is failure number six: a perfect query
against a data model your events never reached.

**Which to ship?** Usually both. The real lesson is that *"the detection works"
is not a property of a rule.* It is a property of a rule **plus** a pipeline
**plus** an output format **plus** the current state of your data model.

---

## Stage 6 — Escaping and precedence

**Backslashes:** the generated SPL contains `"*\\powershell.exe"` while your data
holds one backslash. Whether that matches depends on index-time writing and SPL
unescaping, and it varies by backend version. Do not reason about it — test it,
offline *and* in Splunk.

**Precedence:** the generated query has no grouping parentheses around the OR
branch:

```
Image IN (...) OR OriginalFileName IN (...) CommandLine IN (...)
```

The rule means `(A OR B) AND C`. With C/Python/SQL precedence in your head that
reads as `A OR (B AND C)` — and you would file a bug.

**Splunk evaluates: parentheses → `NOT` → `OR` → `AND`.** `OR` binds tighter than
`AND`, the reverse of most languages. The output is correct; the backend depends
on it.

Consequences: never hand-edit generated SPL without this in mind, and never port
it to another query language by find-and-replace.

---

## The scoreboard

| # | Failure | Layer | Silent? |
|---|---|---|---|
| 1 | no field extraction | `collection/` | yes |
| 2 | correct parser, data re-serialised to `"` | `collection/` | yes |
| 3 | same cause, `TIME_PREFIX` no longer matches | `collection/` | yes, for weeks |
| 4 | XML entities in field values | `collection/` | yes |
| 5 | wrong `source` prefix | `pipelines/` | yes |
| 6 | data model empty / format mismatch | `pipelines/` | mismatch loud, empty model silent |

Five of six silent. **None in `rules/`.**

The rule you were handed in Stage 1 is byte-identical to the rule that works now.
That is the whole workshop.
