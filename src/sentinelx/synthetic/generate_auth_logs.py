"""Generate synthetic login (authentication) logs for Arclight Logistics.

Creates two files:
  data/siem/auth_events.jsonl   - the logs, one JSON event per line
  data/siem/ground_truth.json   - the answer key: which events are attacks

Run from the project folder:
  uv run python -m sentinelx.synthetic.generate_auth_logs
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sentinelx.synthetic.company import ATTACKER_IPS, EMPLOYEES, HOME_IPS, WORKSTATION_IPS

SEED = 42  # fixed seed: the "random" data is identical every run
START = datetime(2026, 10, 5, tzinfo=timezone.utc)  # Monday, 5 Oct 2026
DAYS = 7
OUTPUT_DIR = Path("data/siem")


def make_event(rng, when, host, user, src_ip, outcome, reason=None):
    """Build one login event as a dictionary."""
    return {
        "event_id": f"evt-{rng.randrange(16**8):08x}",
        "timestamp": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "auth",
        "host": host,
        "event_type": "login",
        "user": user,
        "src_ip": src_ip,
        "outcome": outcome,
        "failure_reason": reason,
    }


def normal_activity(rng):
    """Ordinary employee logins: weekdays, roughly office hours, a few typos."""
    events = []
    for day in range(DAYS):
        date = START + timedelta(days=day)
        if date.weekday() >= 5:  # 5 = Saturday, 6 = Sunday
            continue
        for user, info in EMPLOYEES.items():
            # Office hours in India are about 03:30-12:30 UTC.
            when = date + timedelta(hours=rng.uniform(3.5, 5.0))
            working_from_home = rng.random() < 0.3
            if working_from_home:
                host, ip = "vpn-gw-01", HOME_IPS[user]
            else:
                host, ip = "dc-01", WORKSTATION_IPS[info["workstation"]]

            if rng.random() < 0.15:  # a mistyped password before the real login
                events.append(make_event(rng, when, host, user, ip, "failure", "bad_password"))
                when += timedelta(seconds=rng.randint(5, 30))
            events.append(make_event(rng, when, host, user, ip, "success"))
    return events


def brute_force_attack(rng):
    """Scenario 1: many password guesses against ONE account, then a success."""
    ip = ATTACKER_IPS["brute_force"]
    when = datetime(2026, 10, 7, 20, 44, 0, tzinfo=timezone.utc)  # 02:14 on 8 Oct, India time
    events = []
    for _ in range(40):
        events.append(make_event(rng, when, "vpn-gw-01", "jsmith", ip, "failure", "bad_password"))
        when += timedelta(seconds=rng.randint(1, 3))
    events.append(make_event(rng, when, "vpn-gw-01", "jsmith", ip, "success"))
    return events


def password_spray_attack(rng):
    """Scenario 2: ONE common password tried against MANY accounts, slowly."""
    ip = ATTACKER_IPS["password_spray"]
    when = datetime(2026, 10, 9, 18, 0, 0, tzinfo=timezone.utc)
    targets = list(EMPLOYEES) + ["admin", "test", "backup"]  # last three don't exist
    events = []
    for user in targets:
        reason = "bad_password" if user in EMPLOYEES else "unknown_user"
        events.append(make_event(rng, when, "vpn-gw-01", user, ip, "failure", reason))
        when += timedelta(minutes=rng.randint(2, 6))  # slow, to avoid lockouts
    return events


def main():
    rng = random.Random(SEED)
    normal = normal_activity(rng)
    brute = brute_force_attack(rng)
    spray = password_spray_attack(rng)

    all_events = sorted(normal + brute + spray, key=lambda e: e["timestamp"])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_DIR / "auth_events.jsonl", "w") as f:
        for event in all_events:
            f.write(json.dumps(event) + "\n")

    ground_truth = {
        "scenarios": [
            {
                "name": "brute_force",
                "description": "40 failed guesses on jsmith then a successful login",
                "attacker_ip": ATTACKER_IPS["brute_force"],
                "compromised_user": "jsmith",
                "event_ids": [e["event_id"] for e in brute],
            },
            {
                "name": "password_spray",
                "description": "one failed attempt on each of 9 accounts, no success",
                "attacker_ip": ATTACKER_IPS["password_spray"],
                "compromised_user": None,
                "event_ids": [e["event_id"] for e in spray],
            },
        ]
    }
    with open(OUTPUT_DIR / "ground_truth.json", "w") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"Wrote {len(all_events)} events to {OUTPUT_DIR / 'auth_events.jsonl'}")
    print(f"  normal: {len(normal)}  brute force: {len(brute)}  password spray: {len(spray)}")


if __name__ == "__main__":
    main()