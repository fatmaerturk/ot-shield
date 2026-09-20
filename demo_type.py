"""
Typewriter player for the OTShield demo scripts. Types the target script's source
to the terminal with a live typing effect (comments in green, code in cyan), then
runs it - so a recording shows the code first, then the demo executing.

    python demo_type.py                 # defaults to demo_adapt.py
    python demo_type.py demo_attack.py  # any demo script

Tune the pace with an env var (seconds per character):
    set OTSHIELD_TYPE_DELAY=0.010 && python demo_type.py      (CMD)
"""
import sys, os, time, subprocess, pathlib

os.system("")  # enable ANSI colors on Windows terminals

TARGET     = sys.argv[1] if len(sys.argv) > 1 else "demo_adapt.py"
CHAR_DELAY = float(os.environ.get("OTSHIELD_TYPE_DELAY", "0.006"))
LINE_PAUSE = 0.03

CYAN, GREEN, DIM, RST = "\033[36m", "\033[32m", "\033[2m", "\033[0m"

def typeout(text):
    for line in text.split("\n"):
        color = GREEN if line.lstrip().startswith("#") else CYAN
        sys.stdout.write(color)
        for ch in line:
            sys.stdout.write(ch); sys.stdout.flush()
            time.sleep(CHAR_DELAY)
        sys.stdout.write(RST + "\n"); sys.stdout.flush()
        time.sleep(LINE_PAUSE)

src = pathlib.Path(TARGET).read_text(encoding="utf-8")
print(f"{DIM}$ cat {TARGET}{RST}")
typeout(src)
print(f"\n{DIM}$ python {TARGET}{RST}\n")
time.sleep(0.7)
subprocess.run([sys.executable, TARGET])
