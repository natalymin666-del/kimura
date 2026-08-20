# Changelog

## [0.1.0] - 2026-08-20

Initial release of the `kimura-assessment` package:

- Bounded, authorized JSON-over-HTTP assessment workflow for Python 3.10+.
- Command-line and module entry points driven by local JSON configuration.
- Enforcement of scope, authorization dates, request budgets, credential references, timeouts, response-size limits, and no redirects.
- Deterministic, metadata-only results with JSONL persistence and aggregate reporting that excludes raw request, response, and credential data.
