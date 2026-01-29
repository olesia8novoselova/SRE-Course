#!/usr/bin/env python3
import os
import json
import re
from datetime import datetime, timedelta, timezone

import requests

SAGE_API_URL = os.environ.get("SAGE_API_URL", "https://sage.sre-ab.ru/mage/api/search").rstrip("/")
SAGE_API_TOKEN = os.environ.get("SAGE_API_TOKEN", "")

if not SAGE_API_URL:
    raise RuntimeError("SAGE_API_URL is empty")
if not SAGE_API_TOKEN:
    raise RuntimeError("SAGE_API_TOKEN is empty")


def sage_search(query: str, start_iso: str, end_iso: str, source: str = "sla_lab7", size: int = 500):
    # запрос логов в SAGE
    body = {
        "query": query,
        "startTime": start_iso,
        "endTime": end_iso,
        "size": size,
    }

    headers = {
        "Authorization": f"Bearer {SAGE_API_TOKEN}",
        "Content-Type": "application/json",
        "Source": source,
    }

    resp = requests.post(SAGE_API_URL, headers=headers, data=json.dumps(body), timeout=30)
    try:
        data = resp.json()
    except Exception as e:
        return {
            "error": "invalid json from sage",
            "status": resp.status_code,
            "text": resp.text,
            "exception": str(e),
            "body": body,
        }

    if resp.status_code != 200:
        data.setdefault("error", "search failed")
        data.setdefault("status", resp.status_code)
        data.setdefault("body", body)
        return data

    return data

# regexp для статуса в формате [201]
status_bracket_re = re.compile(r"\[(\d{3})\]")

def extract_status(msg: str):
    # HTTP-статус из строки лога

    # формат 1: nginx, статус после кавычек
    parts = msg.split('"')
    if len(parts) >= 3:
        tokens = parts[2].strip().split()
        if tokens and tokens[0].isdigit():
            try:
                return int(tokens[0])
            except ValueError:
                pass

    # формат 2: статус в квадратных скобках [201]
    m = status_bracket_re.search(msg)
    if m:
        try:
            return int(m.group(1))
        except ValueError:
            pass

    return None


def compute_sla_from_hits(hits):
    # SLA по логам пробера для users и events

    total_users = 0
    ok_users = 0

    total_events = 0
    ok_events = 0

    for h in hits:
        msg = h.get("message", "")

        # фильтруем только запросы пробера
        if "python-requests/2.32.5" not in msg:
            continue

        status = extract_status(msg)
        if status is None:
            continue

        # сценарий создания пользователя
        if "POST /api/v0/users" in msg:
            total_users += 1
            if 200 <= status < 300:
                ok_users += 1

        # сценарий создания дежурства
        if "POST /api/v0/events" in msg:
            total_events += 1
            if 200 <= status < 300:
                ok_events += 1

    sla_users = (ok_users / total_users) if total_users > 0 else 0.0
    sla_events = (ok_events / total_events) if total_events > 0 else 0.0

    return {
        "users": {
            "total_scenarios": total_users,
            "ok_scenarios": ok_users,
            "sla": sla_users,
        },
        "events": {
            "total_scenarios": total_events,
            "ok_scenarios": ok_events,
            "sla": sla_events,
        },
    }


if __name__ == "__main__":
    # окно отчёта в минутах
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=60)

    start_iso = start.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    end_iso = end.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    query = 'group="inno_novoselova"'

    data = sage_search(query, start_iso, end_iso, source="sla_lab7", size=500)

    if "error" in data:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        hits = data.get("hits", [])

        sla_data = compute_sla_from_hits(hits)

        result = {
            "from": start_iso,
            "to": end_iso,
            "mode": "search+group+logs",
            "group": "inno_novoselova",
            "users": sla_data["users"],
            "events": sla_data["events"],
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))