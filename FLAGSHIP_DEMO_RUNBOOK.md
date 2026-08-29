# Flagship Demo Runbook

## Before conference

- Laptop charged.
- Flagship repository present.
- Firefox or another default browser available.
- Demo tested once offline.

## Start demo

```console
./scripts/start-flagship-demo.sh
```

## If browser closes

Run the same command again:

```console
./scripts/start-flagship-demo.sh
```

## If Wi-Fi fails

The flagship demo continues to work offline. It opens one local, committed
HTML file and requires no network, API, credentials, Python, or Ollama.

## What this demo is

A synthetic demonstration of a customer-support refund authorization boundary.

## What this demo is not

- Not customer validation.
- Not production validation.
- Not universal agent security.
- Not a real payment transaction.

## 30-second story

EUR 100 limit → EUR 50 allowed and executed → EUR 500 forbidden but executed
→ real synthetic ledger state change → Proof Capsule and causal provenance →
exact EUR 500 retest blocked after the fix → exact EUR 50 retest still works →
Control Fix Verified.

## Technical questions

Point the presenter to the **Technical proof** section in the HTML.
