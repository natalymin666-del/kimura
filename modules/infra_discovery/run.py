import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
TARGET_FILE = BASE_DIR / "targets" / "target.txt"
RESULTS_DIR = BASE_DIR / "results" / "infra"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

target = TARGET_FILE.read_text().strip()

def run(cmd, outfile):
    print(f"[+] Running: {' '.join(cmd)}")
    with open(outfile, "w") as f:
        subprocess.run(cmd, stdout=f, stderr=subprocess.DEVNULL)

# Subdomain discovery
run(["subfinder", "-d", target, "-silent"], RESULTS_DIR / "subdomains.txt")

print("[✓] Infra discovery finished")
