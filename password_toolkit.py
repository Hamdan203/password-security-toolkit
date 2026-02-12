#!/usr/bin/env python3
"""
Password Toolkit
- check_strength(password): returns score and feedback
- generate_password(length): generates a random password
- hash_password(password): returns a JSON string containing salt and hash (PBKDF2-HMAC-SHA256)
- verify_password(password, stored_json): verifies given password against stored JSON
- xor_cipher(text, key): simple reversible XOR cipher (educational only)
"""

import secrets
import string
import hashlib
import json
import argparse
import base64
import datetime
import math

def estimate_entropy_bits(password: str) -> float:
    """
    Rough password entropy estimate:
    entropy ≈ length * log2(character_pool_size)
    """
    if not password:
        return 0.0

    pool = 0
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any((not c.isalnum()) for c in password)

    if has_lower: pool += 26
    if has_upper: pool += 26
    if has_digit: pool += 10
    if has_symbol: pool += 32  # rough estimate of common symbols

    if pool == 0:
        pool = 1

    return len(password) * math.log2(pool)


def check_strength(password: str):
    score = 0
    feedback = []
    length = len(password)
    entropy = estimate_entropy_bits(password)
    security_score = min(int(entropy), 100)

    # Length scoring
    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
        feedback.append("Consider a longer password (12+ chars recommended).")
    else:
        feedback.append("Password too short (8+ chars recommended).")

    # Character variety
    categories = 0
    if any(c.islower() for c in password): categories += 1
    if any(c.isupper() for c in password): categories += 1
    if any(c.isdigit() for c in password): categories += 1
    if any(c in string.punctuation for c in password): categories += 1

    score += categories - 1  # reward variety (0..3)
    if categories < 3:
        feedback.append("Increase character variety: mix upper, lower, digits, and symbols.")

    # Common patterns (simple checks)
    lower = password.lower()
    common = [
    'password','1234','123456','12345678','qwerty','admin','letmein',
    'iloveyou','welcome','monkey','dragon','football','abc123','111111',
    'sunshine','princess','password1','12345','000000'
]

    if any(p in lower for p in common):
        feedback.append("Avoid common words or sequences (e.g., 'password', '1234').")
    else:
        score += 1

    # Final classification
    if score >= 4:
        level = "Strong"
    elif score >= 2:
        level = "Moderate"
    else:
        level = "Weak"

    return {
    "score": score,
    "level": level,
    "feedback": feedback,
    "entropy_bits": round(entropy, 1),
    "security_score": security_score
}

def save_report(password: str, result: dict, filename: str = "security_report.txt"):
    with open(filename, "a", encoding="utf-8") as f:
        f.write(f"Generated at: {datetime.datetime.now()}\n")
        f.write("=== Password Check Report ===\n")
        f.write(f"Password tested: {password}\n")
        f.write(f"Strength: {result['level']}\n")
        f.write(f"Score: {result['score']}\n")
        if result["feedback"]:
            f.write("Feedback:\n")
            for item in result["feedback"]:
                f.write(f"- {item}\n")
        f.write("\n")


def generate_password(length=12):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    # Guarantee at least one of each category if length allows
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd) and any(c in string.punctuation for c in pwd)):
            return pwd

def hash_password(password: str, iterations: int = 200000):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    stored = {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "hash": base64.b64encode(dk).decode('utf-8'),
        "iterations": iterations
    }
    return json.dumps(stored)

def verify_password(password: str, stored_json: str):
    stored = json.loads(stored_json)
    salt = base64.b64decode(stored['salt'].encode('utf-8'))
    stored_hash = base64.b64decode(stored['hash'].encode('utf-8'))
    iterations = int(stored.get('iterations', 200000))
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
    return secrets.compare_digest(dk, stored_hash)

def xor_cipher(text: str, key: str):
    # Simple XOR of bytes - educational only
    tb = text.encode('utf-8')
    kb = key.encode('utf-8')
    out = bytes([tb[i] ^ kb[i % len(kb)] for i in range(len(tb))])
    return out.hex()

def xor_decipher(hextext: str, key: str):
    kb = key.encode('utf-8')
    tb = bytes.fromhex(hextext)
    out = bytes([tb[i] ^ kb[i % len(kb)] for i in range(len(tb))])
    return out.decode('utf-8')

def main():
    parser = argparse.ArgumentParser(description="Password Toolkit - small demo")
    parser.add_argument("--check", type=str, help="Check password strength")
    parser.add_argument("--report", action="store_true", help="Save the strength check result to security_report.txt")
    parser.add_argument("--generate", type=int, help="Generate a random password of given length")
    parser.add_argument("--hash", type=str, help="Hash a password (returns stored JSON)")
    parser.add_argument("--verify", type=str, help="Verify a password against stored JSON (provide stored JSON via --stored)")
    parser.add_argument("--stored", type=str, help="Stored JSON to verify against (use output from --hash)")
    parser.add_argument("--xor", type=str, help="XOR-encrypt a text (educational)")
    parser.add_argument("--xorkey", type=str, default="key", help="Key for XOR cipher")
    args = parser.parse_args()

    if args.check:
        res = check_strength(args.check)
        print("Strength:", res['level'])
        print("Score:", res['score'])
        print("Entropy (bits):", res["entropy_bits"])
        print("Security Score (0–100):", res["security_score"])
        if res['feedback']:
            print("Feedback:")
            for f in res['feedback']:
                print("-", f)

        if args.report:
            save_report(args.check, res, filename="security_report.txt")
            print("Saved report to security_report.txt")

    elif args.generate:
        pwd = generate_password(args.generate)
        print("Generated password:", pwd)

    elif args.hash:
        stored = hash_password(args.hash)
        print("Stored JSON:")
        print(stored)

    elif args.verify:
        if not args.stored:
            print("Error: provide --stored '<stored JSON>'")
            return
        ok = verify_password(args.verify, args.stored)
        print("Password verified?", ok)

    elif args.xor:
        hexed = xor_cipher(args.xor, args.xorkey)
        print("XOR hex:", hexed)
        print("Deciphered:", xor_decipher(hexed, args.xorkey))

    else:
        print("Run with --help for usage.")
	
if __name__ == '__main__':
    main()
