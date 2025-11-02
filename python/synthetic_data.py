"""synthetic_data.py
Utilities for generating synthetic, format-preserving PII used by the simulator.
Seeded for reproducibility.
"""
from __future__ import annotations
import random
import string

RNG = random.Random(42)

def phone_e164():
    # +<country><area><7 digits> (toy generator)
    cc = RNG.choice(['+1', '+33', '+44', '+49'])
    area = RNG.randint(200, 999)
    rest = RNG.randint(1000000, 9999999)
    return f"{cc}{area}{rest}"
def email():
    user = ''.join(RNG.choice(string.ascii_lowercase) for _ in range(8))
    domain = RNG.choice(['example.com','sample.org','test.net'])
    return f"{user}@{domain}"
def national_id():
    # Simple checksum-like pattern (toy only)
    base = ''.join(RNG.choice(string.digits) for _ in range(8))
    checksum = sum(map(int, base)) % 10
    re
