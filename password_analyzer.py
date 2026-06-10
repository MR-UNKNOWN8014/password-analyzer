"""
Password Strength Analyzer
===========================
Analyzes a password using NIST-inspired rules + entropy scoring.

Usage:
    python password_analyzer.py                    # interactive hidden input
    python password_analyzer.py --password abc123  # pass directly as argument
"""

import argparse
import os
import math
from getpass import getpass

# 1: Loading the COMMON PASSWORD LIST

def load_common_passwords(filepath: str) -> set:
    common = set()
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            for line in f:
                common.add(line.strip().lower())
    return common


# 2: Calculate Entropy

def calculate_entropy(password: str) -> float:
    """
        Calculates password entropy in bits.

        Formula: entropy = length * log2(pool_size)

        Pool size is determined by which character types appear in the password:
            - Lowercase letters (a-z)    → +26
            - Uppercase letters (A-Z)    → +26
            - Digits (0-9)               → +10
            - Special characters         → +33

        Higher entropy = harder to brute-force.
        NIST guidelines:
            < 28 bits  → Very Weak
            28–35 bits → Weak
            36–59 bits → Moderate
            60–79 bits → Strong
            80+ bits   → Very Strong
        """
    pool_size = 0

    if any(c.islower() for c in password):
        pool_size += 26
    if any (c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(not c.isalnum() for c in password):
        pool_size += 33

    if pool_size == 0:
        return 0.0

    # log2(pool_size) = bits of randomness per character
    # multiply by length to get total bits
    entropy = len(password) * math.log2(pool_size)
    return round(entropy, 2)

# 3: Run all checks

def analyze_password(password: str, common_passwords: set) -> dict:
    """
        Runs all checks on the password and returns a results dictionary.

        Each check produces:
            - passed (bool): did it pass?
            - message (str): feedback to show the user

        Returns a dict with all check results, a score (0-100), and entropy.
        """
    checks = []
    score = 0

    # Check 1: Minimum length (NIST recommends 8+, 12+ is better)
    if len(password) >= 12:
        checks.append({"passed": True, "message":"Password length is 12+ (excellent)"})
        score += 25
    elif len(password) >=8:
        checks.append({"passed": True, "message":"Password length is 8+ (acceptable but 12+ is better)"})
        score += 15
    else:
        checks.append({"passed": False, "message":f"Password is too short ({len(password)} chars). Use at least 8 (ideally 12+)"})


    # Check 2: Uppercase Letters
    if any(c.isupper() for c in password):
        checks.append({"passed": True, "message":"Password contains uppercase letters"})
        score += 15
    else:
        checks.append({"passed": False, "message":"Passwrod should have atleast one uppercase letter (A-Z)"})


    # Check 3: Lowercase Letters
    if any(c.islower() for c in password):
        checks.append({"passed": True, "message":"password contains lowercase letters"})
        score += 15
    else:
        checks.append({"passed": False, "message":"password should have at least one lowercase letter (a-z)"})


    # Check 4: Digits
    if any(c.isdigit() for c in password):
        checks.append({"passed": True, "message":"password contains digits"})
        score += 15
    else:
        checks.append({"passed": False, "message":"password should have at least one digit (0-9)"})


    # Check 5: Special Characters
    special_chars = set("!@#$%^&*()-_=+[]{}|;:',.<>?/`~\"\\")
    if any(c in special_chars for c in password):
        checks.append({"passed": True, "message":"password contains special characters"})
        score += 15
    else:
        checks.append({"passed": False, "message":"password should have at least one special character(s)"})

    # Check 6: Common Passwords
    if password.lower() in common_passwords:
        checks.append({"passed": False, "message":"Password is common. Do Not use it."})
        score= min(score, 10)
    else:
        checks.append({"passed": True, "message":"Password not found in common password list"})
        score += 15


    # Entropy
    entropy = calculate_entropy(password)

    if entropy >= 80:
        score = min(100, score + 10)
    elif entropy < 28:
        score = max(0, score - 20)

    return {
        "checks": checks,
        "score": min(score, 100),
        "entropy": entropy,
        }

# 4: Dsiplaying the results

def get_grade(score: int) -> tuple:

    if score >= 85:
        return "A", "Very Strong"
    elif score >= 70:
        return "B", "Strong"
    elif score >= 50:
        return "C", "Moderate"
    elif score >= 30:
        return "D", "Weak"
    else:
        return "F", "Very Weak"


def get_entropy_label(entropy: float) -> str:

    if entropy >= 80:
        return "Excellent"
    elif entropy >= 60:
        return "Strong"
    elif entropy >= 36:
        return "Moderate"
    elif entropy >= 28:
        return "Weak"
    else:
        return "Very Weak"


def display_results(results: dict) -> None:
    score = results["score"]
    entropy = results["entropy"]
    checks = results["checks"]
    grade, label = get_grade(score)
    entropy_label = get_entropy_label(entropy)

    # ---- HEADER -----
    print("\n" + "=" * 50)
    print("PASSWORD STRENGTH ANALYZER")
    print("=" * 50)

    # ---- Score Bar----
    bar_filled = int(score/5)   # out of 20 blocks
    bar_empty = 20 - bar_filled
    bar = "[" + "#" * bar_filled + "-" * bar_empty + "]"
    print(f"\n  Score   : {score}/100  {bar}")
    print(f"  Grade   : {grade}  ({label})")
    print(f"  Entropy : {entropy} bits  ({entropy_label})")

    # ---- Individual Checks ----
    print("\n" + "-" * 50)
    print("  CHECKS")
    print("-" * 50)
    for check in checks:
        symbol = "[PASS]" if check["passed"] else "[FAIL]"
        print(f"  {symbol}  {check['message']}")

    # ---- Recommendations ----
    failed = [c for c in checks if not c["passed"]]
    if failed:
        print("\n" + "-" * 50)
        print("  RECOMMENDATIONS")
        print("-" * 50)
        for i, check in enumerate(failed, start=1):
            print(f"  {i}. {check['message']}")

    # ---- NIST Tips ----
    print("\n" + "-" * 50)
    print("  NIST TIP: Use a passphrase (4+ random words) for")
    print("  high entropy that's also easy to remember.")
    print("  Example: 'correct-horse-battery-staple'")
    print("=" * 50 + "\n")


# 5: Entry Point (argparse + getpass)
def main():
    """
        Entry point. Handles both input methods:
            1. --password flag (passed directly as CLI argument)
            2. Interactive prompt (getpass — characters hidden while typing)
        """

    # Argument Parser
    parser = argparse.ArgumentParser(
        description="Analyze the strength of a password using NIST-inspired rules and entropy scoring.",
        epilog="Tip: Run without --password for a secure hidden input prompt."
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password to analyze (use interactive mode for better security)"
    )

    args = parser.parse_args()

    # Getting the password
    if args.password:
        # User passed '--password' on the command line
        password = args.password
        print("\n[NOTE] Password passed as argument — visible in terminal history.")
        print("Use interactive mode for better security.\n")
    else:
        # Interactive mode: getpass hides input as the user types
        print("\nPassword Strength Analyzer")
        print("Enter your password below (input is hidden):")
        password = getpass("  Password: ")

    if not password:
        print("\n[ERROR] No password provided. Exiting.")
        return

    # --- Load common passwords ---
    # Build the path relative to this script file so it works from any directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    common_passwords_path = os.path.join(script_dir, "common_passwords.txt")
    common_passwords = load_common_passwords(common_passwords_path)

    # --- Run analysis ---
    results = analyze_password(password, common_passwords)

    # --- Display results ---
    display_results(results)

# This block only runs when the script is executed directly.
# If someone imports this file as a module, main() won't auto-run.
if __name__ == "__main__":
    main()