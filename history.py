# history.py — Scan history management

import json
import os
from datetime import datetime


HISTORY_FILE = 'scan_history.json'


def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []


def save_scan(scan_target, scan_type, findings, risk_score, counts):
    history = load_history()
    entry = {
        'id': len(history) + 1,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'target': scan_target,
        'type': scan_type,
        'risk_score': risk_score,
        'total': len(findings),
        'counts': counts,
        'findings': findings[:50]
    }
    history.insert(0, entry)
    history = history[:20]
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception as e:
        print(f"History save error: {e}")
    return entry


def delete_history():
    if os.path.exists(HISTORY_FILE):
        os.remove(HISTORY_FILE)


def get_scan_by_id(scan_id):
    history = load_history()
    for entry in history:
        if entry.get('id') == scan_id:
            return entry
    return None