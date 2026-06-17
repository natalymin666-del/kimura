import subprocess
from datetime import datetime

TARGETS = [
    "prime-staging.coinbase.com",
    "api-public.sandbox.exchange.coinbase.com",
    "api.coinbase.com",
    "exchange.coinbase.com"
]

PORTS = "22,2375,3000,5601,8080,8443"
OUTPUT = "results/coinbase.txt"


def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError:
        return "error"


with open(OUTPUT, "w") as f:
    f.write(f"[Kimura Infra Discovery]\n")
    f.write(f"Scan date: {datetime.utcnow()} UTC\n\n")

    for target in TARGETS:
        f.write("=" * 60 + "\n")
        f.write(f"TARGET: {target}\n\n")

        f.write("[DNS]\n")
        f.write(run(f"dig {target} +short") + "\n\n")

        f.write("[HEADERS]\n")
        f.write(run(f"curl -I https://{target}") + "\n\n")

        f.write("[NMAP]\n")
        f.write(run(f"nmap -Pn -p {PORTS} {target}") + "\n\n")

print("✔ Infra discovery completed. Results saved to results/coinbase.txt")
