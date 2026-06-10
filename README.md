A Python CLI tool that evaluates password strength using **real security principles**, Shannon entropy scoring and NIST SP 800-63B guidelines, the same standards used in enterprise security systems.

Built from scratch as a portfolio project while studying **Python**, **Cybersecurity (CISSP)**, and **Cloud/DevOps**.

---

## 📸 Demo

```
==================================================
       PASSWORD STRENGTH ANALYZER
==================================================

  Score   : 100/100  [####################]
  Grade   : A  (Very Strong)
  Entropy : 124.83 bits  (Excellent)

--------------------------------------------------
  CHECKS
--------------------------------------------------
  [PASS]  Length is 12+ characters (excellent)
  [PASS]  Contains uppercase letters
  [PASS]  Contains lowercase letters
  [PASS]  Contains digits (0-9)
  [PASS]  Contains special characters
  [PASS]  Not found in common passwords list

--------------------------------------------------
  NIST TIP: Use a passphrase (4+ random words) for
  high entropy that's also easy to remember.
  Example: 'correct-horse-battery-staple'
==================================================
```

---

## ✨ Features

- **Entropy scoring**: calculates bits of randomness using the Shannon entropy formula, the real metric security engineers use to measure brute force resistance
- **NIST SP 800-63B compliance checks**: validates length, uppercase, lowercase, digits, and special characters against NIST guidelines
- **Common password detection**: instantly flags passwords found on known breach lists using O(1) set lookup
- **Dual input modes**: interactive hidden input (characters invisible while typing) or `--password` CLI argument
- **Scored output**: 0 to 100 score with letter grade (A–F), strength label, and per-check pass/fail breakdown
- **Actionable recommendations**: tells you exactly what to fix, not just that you failed
- **Zero external dependencies**: built entirely on Python's standard library

---

## 🚀 Getting Started

### Requirements

- Python 3.7 or higher
- No pip installs needed, uses stdlib only (`argparse`, `getpass`, `math`, `os`)

### Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/password-analyzer.git
cd password-analyzer
```

### Run it

```bash
# Interactive mode: recommended, input is hidden as you type
python password_analyzer.py

# Pass password directly as a CLI argument
python password_analyzer.py --password "YourPasswordHere"

# View help and all available options
python password_analyzer.py --help
```

---

## 📂 Project Structure

```
password_analyzer/
│
├── password_analyzer.py      # Main script. All logic lives here
├── common_passwords.txt      # Blacklist of known weak/common passwords
├── requirements.txt          # No external dependencies (stdlib only)
└── README.md                 # You are here
```

---

## 🧠 How It Works

### 1. Entropy Calculation

Entropy measures how hard a password is to brute force, expressed in bits.

```
entropy = password_length × log₂(character_pool_size)
```

The pool size grows based on which character types are present:

|Character Type|Characters|Pool Contribution|
|---|---|---|
|Lowercase letters|a–z|+26|
|Uppercase letters|A–Z|+26|
|Digits|0–9|+10|
|Special characters|!@#$%^ etc.|+33|

**Example:** A 12-character password using all four types has a pool of 95. `12 × log₂(95) = 78.7 bits` → Strong ✅

### 2. Entropy Benchmarks (NIST Guidelines)

|Entropy (bits)|Rating|
|---|---|
|Less than 28|Very Weak|
|28 – 35|Weak|
|36 – 59|Moderate|
|60 – 79|Strong|
|80+|Very Strong|

### 3. Scoring System

Each check contributes to a score out of 100:

|Check|Points|
|---|---|
|Length 12+ characters|25 pts|
|Length 8+ characters|15 pts|
|Contains uppercase|15 pts|
|Contains lowercase|15 pts|
|Contains digits|15 pts|
|Contains special characters|15 pts|
|Not in common passwords list|15 pts|
|Entropy bonus (80+ bits)|+10 pts|
|Entropy penalty (under 28 bits)|−20 pts|

> ⚠️ If a password is found in the common passwords list, the score is hard-capped at 10 regardless of other checks.

### 4. Grading Scale

|Score|Grade|Label|
|---|---|---|
|85–100|A|Very Strong|
|70–84|B|Strong|
|50–69|C|Moderate|
|30–49|D|Weak|
|0–29|F|Very Weak|

---

## 🔒 Security Concepts Applied

This project directly implements concepts from **CISSP Domain 1: Security & Risk Management** and **NIST SP 800-63B (Digital Identity Guidelines)**:

- **Password entropy**: quantifying unpredictability as a security metric
- **Minimum length requirements**: NIST recommends 8 characters minimum, 12+ preferred
- **Complexity rules**: character variety to increase the effective key space
- **Blocklist checking**: rejecting commonly used and previously breached passwords
- **Secure input handling**: `getpass` prevents shoulder surfing and terminal history exposure

---

## 🧰 Python Concepts Used

|Concept|Where Used|
|---|---|
|`argparse`|CLI argument parsing (`--password` flag, `--help` menu)|
|`getpass`|Hidden password input in interactive mode|
|`math.log2()`|Shannon entropy calculation|
|`set`|O(1) lookup for common password matching|
|f-strings|Dynamic message formatting|
|List comprehensions|Filtering failed checks for recommendations|
|File I/O|Loading `common_passwords.txt` from disk|
|`os.path`|Building cross-platform file paths|
|Type hints|`str`, `float`, `int`, `dict`, `tuple`, `set` on all functions|
|Tuple unpacking|`grade, label = get_grade(score)`|

---

Built with Python 3 · No external dependencies · NIST SP 800-63B aligned
