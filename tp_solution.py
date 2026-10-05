import json
import re
import math
import hashlib
import hmac as hmac_lib
from collections import Counter, deque

_ZIGBEE_RE = re.compile(r"topic '(?:[^/']+)/([^']+)',\s*payload '({.*})'")
_ZWAVE_RE = re.compile(
    r"\[(Node \d+)\]\s+Value updated:\s+(\S+)\s+[\d.\-]+\s*=>\s*([\d.\-]+)"
)


def parse_zigbee_line(line):
    m = _ZIGBEE_RE.search(line)
    if not m:
        return None
    try:
        payload = json.loads(m.group(2))
    except json.JSONDecodeError:
        return None
    return {"device": m.group(1), "payload": payload}


def parse_zwave_line(line):
    m = _ZWAVE_RE.search(line)
    if not m:
        return None
    try:
        value = float(m.group(3))
    except ValueError:
        return None
    return {"node": m.group(1), "command_class": m.group(2), "value": value}


def parse_ha_line(line):
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


ZIGBEE_KNOWN_FIELDS = {
    "power": "power",
    "current": "current",
    "voltage": "voltage",
    "energy": "energy",
    "battery": "battery",
    "linkquality": "link_quality",
}

SAFETY_CRITICAL_FIELDS = {"alarm", "tamper", "contact"}

HA_UNIT_TO_METRIC = {"W": "power", "V": "voltage", "A": "current", "kWh": "energy"}


def _to_float(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def normalize_zigbee(parsed):
    device_id = parsed["device"]
    events = []
    for field, value in parsed["payload"].items():
        if field == "device":
            continue
        if field in ZIGBEE_KNOWN_FIELDS:
            name, critical, num = ZIGBEE_KNOWN_FIELDS[field], False, _to_float(value)
        elif field in SAFETY_CRITICAL_FIELDS:
            name, critical, num = field, True, _to_float(value)
        else:
            # champ inconnu : on le garde tel quel
            name, critical, num = f"unknown_{field}", False, None
        events.append({
            "device_id": device_id,
            "protocol": "zigbee",
            "metric_name": name,
            "metric_value": num,
            "safety_critical": critical,
            "raw": {field: value},
        })
    return events


def normalize_zwave(parsed):
    return [{
        "device_id": parsed["node"],
        "protocol": "zwave",
        "metric_name": "power",
        "metric_value": parsed["value"],
        "safety_critical": False,
        "raw": dict(parsed),
    }]


def normalize_ha(parsed):
    state = parsed.get("state")
    unit = parsed.get("unit")

    value = None
    if isinstance(state, str):
        try:
            value = float(state)
        except ValueError:
            pass
    else:
        value = _to_float(state)

    return [{
        "device_id": parsed.get("entity_id"),
        "protocol": "ha",
        "metric_name": HA_UNIT_TO_METRIC.get(unit, unit if unit else "state"),
        "metric_value": value,
        "safety_critical": False,
        "raw": dict(parsed),
    }]


def naive_ha_load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def streaming_parse_ha(path):
    buf = ""
    depth = 0
    with open(path, encoding="utf-8") as f:
        for line in f:
            for ch in line:
                if depth == 0 and ch != "{":
                    continue
                buf += ch
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        yield json.loads(buf)
                        buf = ""


def deadband_filter(events, delta):
    last_sent = {}
    result = []
    for e in events:
        value = e.get("metric_value")
        # les événements critiques et sans valeur passent toujours
        if e.get("safety_critical") or value is None:
            result.append(e)
            continue
        key = (e.get("device_id"), e.get("metric_name"))
        if key not in last_sent or abs(value - last_sent[key]) >= delta:
            result.append(e)
            last_sent[key] = value
    return result


def detect_power_surge(events, threshold_w=2000):
    alerts = []
    for e in events:
        value = e.get("metric_value")
        if e.get("metric_name") == "power" and value is not None and value > threshold_w:
            alerts.append({
                "rule": "power_surge",
                "device_id": e.get("device_id"),
                "metric_name": "power",
                "metric_value": value,
            })
    return alerts


def detect_replay(events, window=3):
    alerts = []
    last_value = {}
    run_count = {}
    alerted = {}

    for e in events:
        val = e.get("metric_value")
        if val is None:
            continue
        key = (e.get("device_id"), e.get("metric_name"))
        if key in last_value and last_value[key] == val:
            run_count[key] += 1
        else:
            last_value[key] = val
            run_count[key] = 1
            alerted[key] = False

        if run_count[key] >= window and not alerted[key]:
            alerts.append({
                "rule": "replay",
                "device_id": key[0],
                "metric_name": key[1],
                "metric_value": val,
                "repeat_count": run_count[key],
            })
            alerted[key] = True
    return alerts


def detect_rogue_device(events, known_devices):
    alerts = []
    for e in events:
        if e.get("device_id") not in known_devices:
            alerts.append({
                "rule": "rogue_device",
                "device_id": e.get("device_id"),
                "metric_name": e.get("metric_name"),
                "metric_value": e.get("metric_value"),
            })
    return alerts


def detect_event_storm(events, window_events=20, max_per_device=8):
    # events : liste des device_id au niveau message, pas les événements normalisés
    window = deque(maxlen=window_events)
    counts = Counter()
    in_storm = set()
    alerts = []

    for device_id in events:
        if len(window) == window.maxlen:
            old = window.popleft()
            counts[old] -= 1
            if counts[old] <= max_per_device:
                in_storm.discard(old)

        window.append(device_id)
        counts[device_id] += 1

        if counts[device_id] > max_per_device and device_id not in in_storm:
            alerts.append({
                "rule": "event_storm",
                "device_id": device_id,
                "count_in_window": counts[device_id],
                "window_events": window_events,
            })
            in_storm.add(device_id)
    return alerts


def load_zigbee_events(path):
    events = []
    with open(path) as f:
        for line in f:
            parsed = parse_zigbee_line(line)
            if parsed:
                events.extend(normalize_zigbee(parsed))
    return events


def load_healthy_events(zigbee_path, zwave_path, ha_path):
    events = load_zigbee_events(zigbee_path)
    with open(zwave_path) as f:
        for line in f:
            parsed = parse_zwave_line(line)
            if parsed:
                events.extend(normalize_zwave(parsed))
    with open(ha_path) as f:
        for line in f:
            parsed = parse_ha_line(line)
            if parsed:
                events.extend(normalize_ha(parsed))
    return events


def run_pipeline_provisoire(events, delta=1.0, window=3):
    after = deadband_filter(events, delta)
    return {
        "n_events_avant": len(events),
        "n_events_apres": len(after),
        "replay_avant": detect_replay(events, window=window),
        "replay_apres": detect_replay(after, window=window),
    }


def naive_hash_device_id(name):
    return hashlib.sha256(name.encode()).hexdigest()[:20]


def hmac_pseudonymize(protocol, name, secret):
    message = f"{protocol}:{name}".encode()
    return hmac_lib.new(secret, message, hashlib.sha256).hexdigest()[:20]


def dictionary_attack(observed_hashes, dictionary, hash_fn):
    found = {}
    for guess in dictionary:
        h = hash_fn(guess)
        if h in observed_hashes:
            found[h] = guess
    return found


def shannon_entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def detect_high_entropy_unknown(events, threshold=4.5, min_length=8):
    alerts = []
    for e in events:
        name = e.get("metric_name", "")
        if not name.startswith("unknown_") or e.get("metric_value") is not None:
            continue
        raw_value = next(iter((e.get("raw") or {}).values()), None)
        if not isinstance(raw_value, str) or len(raw_value) < min_length:
            continue
        h = shannon_entropy(raw_value)
        if h > threshold:
            alerts.append({
                "rule": "high_entropy_unknown",
                "device_id": e.get("device_id"),
                "metric_name": name,
                "raw_value": raw_value,
                "entropy": h,
            })
    return alerts


MITRE_ARTIFACT_LABELS = {
    "unmapped_linux_cmd": "A10 Privilege Escalation",
    "unmapped_net_cmd": "A11 Reverse Shell",
    "unmapped_persist_cmd": "A12 Persistence Cron/Systemd",
    "unmapped_cred_access": "A13 Credential Access",
    "unmapped_download_cmd": "A14 Command and Control / Dropper",
    "unmapped_lateral_cmd": "A15 Lateral Movement",
}


def detect_mitre_artifact(events):
    alerts = []
    for e in events:
        name = e.get("metric_name", "")
        if not name.startswith("unknown_"):
            continue
        key = name[len("unknown_"):]
        if key not in MITRE_ARTIFACT_LABELS:
            continue
        alerts.append({
            "rule": "mitre_artifact",
            "device_id": e.get("device_id"),
            "metric_name": name,
            "technique": MITRE_ARTIFACT_LABELS[key],
            "command": e.get("raw", {}).get(key),
        })
    return alerts


def run_pipeline(zigbee_path, zwave_path, delta=1.0, known_devices=None,
                 power_threshold=2000):
    known_devices = known_devices or set()
    events, zigbee_msgs, zwave_msgs = [], [], []

    with open(zigbee_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = parse_zigbee_line(line)
            if parsed:
                zigbee_msgs.append(parsed["device"])
                events.extend(normalize_zigbee(parsed))

    with open(zwave_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            parsed = parse_zwave_line(line)
            if parsed:
                # "Node 003" -> "node_003", comme dans la baseline
                parsed["node"] = parsed["node"].lower().replace(" ", "_")
                zwave_msgs.append(parsed["node"])
                events.extend(normalize_zwave(parsed))

    after = deadband_filter(events, delta)
    n_unknown = sum(e["metric_name"].startswith("unknown_") for e in events)

    power = detect_power_surge(events, power_threshold)
    replay_avant = detect_replay(events)
    replay_apres = detect_replay(after)
    storm = detect_event_storm(zigbee_msgs) + detect_event_storm(zwave_msgs)
    entropy = detect_high_entropy_unknown(events)
    mitre = detect_mitre_artifact(events)

    # une alerte par appareil distinct
    rogue = sorted({a["device_id"] for a in detect_rogue_device(events, known_devices)},
                   key=str)

    return {
        "n_messages": len(zigbee_msgs) + len(zwave_msgs),
        "n_events": len(events),
        "n_unknown": n_unknown,
        "pct_unknown": 100 * n_unknown / len(events) if events else 0.0,
        "n_after_deadband": len(after),
        "pct_filtered": 100 * (1 - len(after) / len(events)) if events else 0.0,
        "alerts": {
            "power_surge": len(power),
            "replay_avant_deadband": len(replay_avant),
            "replay_apres_deadband": len(replay_apres),
            "rogue_device": len(rogue),
            "event_storm": len(storm),
            "entropy": len(entropy),
            "mitre": len(mitre),
        },
        "power_alerts": power,
        "storm_alerts": storm,
        "rogue_devices": rogue,
        "devices_distinct": sorted({e["device_id"] for e in events}, key=str),
        "events": events,
    }


if __name__ == "__main__":
    KNOWN_DEVICES = {
        "zigbee_prise_5", "zigbee-switch-inwall-4", "zigbee-alarm-1",
        "zigbee-pir-1", "node_002", "node_003",
    }
    result = run_pipeline("data/zigbee_large_sample.log",
                          "data/zwave_large_sample.log",
                          delta=1.0, known_devices=KNOWN_DEVICES)
    for k in ("n_messages", "n_events", "n_unknown", "pct_unknown",
              "n_after_deadband", "pct_filtered", "alerts"):
        print(k, "=", result[k])
