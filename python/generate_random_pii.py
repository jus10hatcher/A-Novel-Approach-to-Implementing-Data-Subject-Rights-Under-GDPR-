#!/usr/bin/env python3
"""
generate_random_pii.py

Synthetic PII generator for GDPR benchmarking experiments.

Features:
- Generates realistic but entirely synthetic PII
- Deterministic output via random seed
- Supports CSV or JSONL output
- Field formats align with GDPR-relevant identifiers
- No external dependencies (stdlib only)

Fields generated:
- subject_id
- first_name
- last_name
- email
- phone_e164
- street
- city
- postal_code
- country
- date_of_birth
"""

import argparse
import csv
import json
import random
import string
from datetime import date, timedelta

# -------------------------
# Utilities
# -------------------------

FIRST_NAMES = [
    "Alice","Bob","Carol","David","Eve","Frank","Grace","Heidi","Ivan","Judy",
    "Mallory","Niaj","Olivia","Peggy","Rupert","Sybil","Trent","Victor","Wendy"
]

LAST_NAMES = [
    "Smith","Johnson","Williams","Brown","Jones","Miller","Davis","Garcia",
    "Rodriguez","Wilson","Martinez","Anderson","Taylor","Thomas","Moore"
]

STREETS = [
    "Main St","Oak Ave","Pine Rd","Maple Dr","Cedar Ln",
    "Elm St","Birch Way","Spruce Ct","Willow Blvd"
]

CITIES = [
    "Berlin","Paris","Madrid","Rome","Vienna",
    "Amsterdam","Brussels","Zurich","Stockholm","Oslo"
]

COUNTRIES = ["DE","FR","ES","IT","NL","BE","CH","SE","NO","DK"]

EMAIL_DOMAINS = ["example.com","mail.test","sample.org","synthetic.net"]

def random_date(start_year=1940, end_year=2005):
    start = date(start_year, 1, 1)
    end = date(end_year, 12, 31)
    delta = end - start
    return start + timedelta(days=random.randint(0, delta.days))

def random_phone_e164():
    country_code = random.choice(["+1","+33","+49","+34","+39","+31","+41","+46","+47","+45"])
    number = "".join(random.choice(string.digits) for _ in range(9))
    return country_code + number

def random_postal():
    return "".join(random.choice(string.digits) for _ in range(5))

def random_email(first, last):
    user = f"{first}.{last}{random.randint(1,9999)}".lower()
    return f"{user}@{random.choice(EMAIL_DOMAINS)}"

# -------------------------
# Record generator
# -------------------------

def generate_record(idx):
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    dob = random_date()
    record = {
        "subject_id": f"user-{idx}",
        "first_name": first,
        "last_name": last,
        "email": random_email(first, last),
        "phone_e164": random_phone_e164(),
        "street": f"{random.randint(1,999)} {random.choice(STREETS)}",
        "city": random.choice(CITIES),
        "postal_code": random_postal(),
        "country": random.choice(COUNTRIES),
        "date_of_birth": dob.isoformat()
    }
    return record

# -------------------------
# Main
# -------------------------

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic PII dataset")
    parser.add_argument("--rows", type=int, required=True, help="Number of records to generate")
    parser.add_argument("--out", type=str, required=True, help="Output file (.csv or .jsonl)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed (default: 42)")
    args = parser.parse_args()

    random.seed(args.seed)

    is_csv = args.out.lower().endswith(".csv")
    is_jsonl = args.out.lower().endswith(".jsonl")

    if not (is_csv or is_jsonl):
        raise ValueError("Output file must end with .csv or .jsonl")

    if is_csv:
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            writer = None
            for i in range(args.rows):
                rec = generate_record(i)
                if writer is None:
                    writer = csv.DictWriter(f, fieldnames=rec.keys())
                    writer.writeheader()
                writer.writerow(rec)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            for i in range(args.rows):
                rec = generate_record(i)
                f.write(json.dumps(rec) + "\n")

    print(f"Generated {args.rows} synthetic PII records → {args.out}")

if __name__ == "__main__":
    main()
