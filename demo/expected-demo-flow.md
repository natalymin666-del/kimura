# Expected 2–3 minute presenter flow

Expected describes workflow and report structure, not guaranteed model outcomes.
Use the generated CLI summary and report.html for actual numbers.

## 0:00–0:20 — What Kimura is

“Kimura is an AI-agent security assessment platform. It validates agent
behavior under authorized, controlled conditions and verifies whether a fix
holds under exact retesting.”

## 0:20–0:40 — Show authorized configuration

Open demo/customer.demo.json. Point out authorization, loopback-only Ollama,
llama3.2:3b, synthetic target and tool, selected fixture, trial count, and
exclusions.

“This is an explicitly bounded assessment, not a production target.”

## 0:40–1:20 — Run assessment

~~~console
python3 -m kimura_assessment assess demo/customer.demo.json \
  --output ./demo-output
~~~

Read the generated summary: assessment ID, runtime, scenario, trials, baseline
risk and outcomes, remediation, retest counts, and final status.

## 1:20–1:50 — Explain baseline and evidence

“Kimura does not only check whether a model says something unsafe. It separates
the model's proposed action, the tool authorization decision, local simulated
execution, validated impact, and exact retest after remediation.”

Open the baseline and evidence sections of demo-output/report.html. Evidence
contains classifications and digests, not raw prompts or model responses.

## 1:50–2:15 — Explain remediation and exact retest

“The policy is applied locally, then the exact same fixture, trial count, and
seeds are replayed. The retest tells us whether this tested path was blocked
after remediation.”

Show remediation, retest blocked actions, and validated impact as actually
reported. Do not claim a pass if the generated result does not pass.

## 2:15–2:40 — Open report.html

Show executive summary, finding, methodology, evidence summary, remediation,
retest results, limitations, and safety controls.

## 2:40–3:00 — Explain customer value

“The value is not merely a model screenshot. Kimura gives security and
engineering teams a defensible chain from proposal to policy decision to
simulated execution to validated impact, followed by exact remediation retest
and a customer-ready report.”
