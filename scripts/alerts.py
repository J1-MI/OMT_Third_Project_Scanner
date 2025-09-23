#!/usr/bin/env python3
import os, requests, json
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK")

def send_alert(text):
    if SLACK_WEBHOOK:
        try:
            requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=5)
        except Exception as e:
            print("Slack send failed:", e)
    else:
        print("[ALERT]", text)
