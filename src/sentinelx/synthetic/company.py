"""The fictional company that SentinelX investigates.

Every synthetic log generator imports from this file, so the same users,
computers and IP addresses appear consistently across all data sources.
"""

COMPANY_NAME = "Arclight Logistics"
DOMAIN = "arclight.example"  # .example is reserved: it can never be a real site

# Employees: username -> details.
# "workstation" is the computer each person normally uses.
EMPLOYEES = {
    "jsmith": {"name": "John Smith", "role": "finance", "workstation": "WS-001"},
    "pkumar": {"name": "Priya Kumar", "role": "engineering", "workstation": "WS-002"},
    "adsouza": {"name": "Anita D'Souza", "role": "hr", "workstation": "WS-003"},
    "mlopez": {"name": "Maria Lopez", "role": "sales", "workstation": "WS-004"},
    "rnair": {"name": "Rahul Nair", "role": "engineering", "workstation": "WS-005"},
    "kchen": {"name": "Kevin Chen", "role": "it_admin", "workstation": "WS-006"},
}

# Each workstation's private (internal) IP address.
WORKSTATION_IPS = {
    "WS-001": "10.10.4.21",
    "WS-002": "10.10.4.37",
    "WS-003": "10.10.4.42",
    "WS-004": "10.10.4.55",
    "WS-005": "10.10.4.63",
    "WS-006": "10.10.4.70",
}

# Systems people log in to.
SERVERS = {
    "vpn-gw-01": "VPN gateway: employees connect here when working from home",
    "dc-01": "Domain controller: checks office logins",
}

# Public IPs employees use from home. Taken from 198.51.100.0/24,
# a range reserved for documentation, so it belongs to no real computer.
HOME_IPS = {
    "jsmith": "198.51.100.10",
    "pkumar": "198.51.100.11",
    "adsouza": "198.51.100.12",
    "mlopez": "198.51.100.13",
    "rnair": "198.51.100.14",
    "kchen": "198.51.100.15",
}

# Attacker IPs, from 203.0.113.0/24 (another documentation range).
ATTACKER_IPS = {
    "brute_force": "203.0.113.45",
    "password_spray": "203.0.113.77",
}