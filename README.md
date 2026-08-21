# Kimura assessment

`kimura_assessment` is a small, standard-library Python package for one bounded,
authorized JSON-over-HTTP assessment interaction. It is the packaged form of
the Step 1–6 assessment workflow; the other research scripts in this repository
are not part of this distribution.

## Installation

Python 3.10 or newer is required. From a checkout:

```console
python -m pip install .
```

For local development, use an editable install:

```console
python -m pip install --editable .
```

The package has no runtime dependencies. Build artifacts can be created with
`python -m build` (the build tool is only needed for that command).

## Configuration

The CLI reads a local JSON configuration. The following is a complete shape;
replace the example values with an explicitly approved assessment:

```json
{
  "contract": {
    "assessment_id": "asm-001",
    "client_name": "Example BV",
    "assessor_name": "Kimura Security",
    "authorized_by": "approval-42",
    "objectives": ["Evaluate prompt-injection resistance"],
    "scope": ["https://example.test"],
    "start_date": "2026-08-20",
    "end_date": "2026-08-22",
    "exclusions": ["production data export"],
    "credential_references": ["env://KIMURA_ASSESSMENT_TOKEN"],
    "max_requests": 1
  },
  "target": {
    "endpoint": "https://example.test/chat",
    "input_path": "messages.0.content",
    "response_path": "choices.0.message.content",
    "credential_reference": "env://KIMURA_ASSESSMENT_TOKEN",
    "timeout": 15.0,
    "max_response_bytes": 1048576
  },
  "input_text": "assessment input",
  "request_json": {"messages": [{"role": "user"}]}
}
```

`credential_references` identify credentials held outside the configuration.
For `env://NAME`, the adapter reads `NAME` only at request time. Other opaque
references map to a stable `KIMURA_CREDENTIAL_*` environment variable name.
Never put a token, cookie, password, or other credential material in the JSON
file or source control. Protect the configuration file because `input_text` and
the request template are sent to the authorized endpoint at runtime.

## CLI usage

After installation, run one interaction with either the console script or the
module form:

```console
export KIMURA_ASSESSMENT_TOKEN='runtime-only-secret'
kimura-assessment assessment.json
# equivalent:
python -m kimura_assessment assessment.json
```

The command prints only the safe result metadata JSON. Operational failures are
reported without target, request, response, or credential contents. `--report`
requires `--persist`:

```console
kimura-assessment assessment.json \
  --persist results/assessment.jsonl \
  --report results/assessment-report.json
```

For a deterministic, local-only Conference Demo v1, run:

```console
python3 -m kimura_assessment demo
```

The demo uses only a loopback mock server, a fixed non-secret placeholder
credential, and the same contract, runner, persistence, and reporting safety
paths as a configured assessment. To also write safe local metadata files:

```console
python3 -m kimura_assessment demo \
  --persist results/conference-demo.jsonl \
  --report results/conference-demo-report.json
```

## Persistence and reporting

`--persist` appends one deterministic JSON object per line to a local JSONL
file. The stored `AssessmentResult` contains the assessment ID, execution
number, authorization date, status, response byte length, and SHA-256 digest;
it does not retain raw input, request, response, or credential data.

The optional report is an aggregate of persisted safe results, sorted
deterministically by assessment ID and execution number. It includes counts,
assessment IDs, total response bytes, and the individual safe result records.
It is metadata reporting, not a transcript.

## Safety guarantees

Each run is constrained by the existing assessment contract and adapter:

- the target must be an HTTP(S) URL inside the declared scope;
- the credential reference must be declared and credential material is resolved
  only from the runtime environment;
- the authorization window and positive request budget are enforced before
  dispatch, and failed attempts consume budget;
- redirects are disabled, response size is bounded, and the expected JSON paths
  must resolve to text; and
- persistence, reports, result JSON, and operational error messages exclude raw
  input, request, response, and credential values.

These controls support an authorized assessment workflow; they do not grant
authorization. Obtain written permission and define scope, exclusions, dates,
and request limits before running it. Keep generated JSONL files and reports
access-controlled.

## Tests and build validation

Run the complete test suite from the repository root:

```console
python -m unittest discover -s tests -p 'test_*.py' -v
```

The GitHub Actions workflow runs that suite on Python 3.10, 3.11, and 3.12,
then builds the source and wheel distributions.
