#!/usr/bin/env python3
import sys, os
ROOT = os.path.dirname(os.path.dirname(__file__)) if __file__ else "."
sys.path.insert(0, ROOT)
from scripts.worker import enqueue
if len(sys.argv)<2:
    print("Usage: python scripts/queue_from_file.py targets.txt")
    sys.exit(1)
fn=sys.argv[1]
with open(fn,"r",encoding="utf-8") as f:
    for line in f:
        line=line.strip()
        if not line or line.startswith("#"): continue
        enqueue(line)
        print("Enqueued:", line)
