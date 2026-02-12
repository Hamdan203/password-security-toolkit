# Password Security Toolkit

Author: Hamdan Ahmed

---

## Overview

The Password Security Toolkit is a Python-based cybersecurity application that evaluates password strength using entropy-based mathematical modeling, heuristic pattern detection, and character diversity analysis.

The project includes both:

- A Command-Line Interface (CLI) tool
- A Graphical User Interface (GUI) desktop application built with Tkinter

The toolkit demonstrates practical cybersecurity principles including entropy estimation, secure hashing, and password vulnerability detection.

---

## Key Features

- Password strength classification (Weak / Moderate / Strong)
- Entropy-based security estimation (bits calculation)
- Security score scaling (0–100)
- Detection of common leaked password patterns
- Secure password hashing using PBKDF2-HMAC-SHA256 with salting
- XOR encryption demonstration (educational purposes)
- Command-line interface using argparse
- Desktop GUI application (Tkinter)
- Automated timestamped report generation
- Modular function-based architecture

---

## Security Concepts Implemented

### 1. Entropy Estimation

Password entropy is calculated using:

entropy ≈ length × log₂(character_pool_size)

Character pool size is determined based on:
- Lowercase letters (26)
- Uppercase letters (26)
- Digits (10)
- Symbols (~32 estimated)

Higher entropy values indicate stronger resistance to brute-force attacks.

---

### 2. Heuristic Pattern Detection

The toolkit detects common leaked password patterns including:
- Common words (e.g., "password", "admin")
- Numeric sequences (e.g., "1234", "111111")
- Frequently used weak combinations

---

### 3. Cryptographic Hashing

Secure password hashing is implemented using:

PBKDF2-HMAC-SHA256 with salting

This prevents:
- Rainbow table attacks
- Direct password storage vulnerabilities

---

### 4. Security Score Modeling

Entropy is scaled into a professional 0–100 Security Score to provide intuitive feedback for users.

---

## Technologies Used

- Python
- Argparse (CLI argument parsing)
- Tkinter (GUI development)
- PBKDF2-HMAC-SHA256 cryptographic hashing
- Mathematical entropy modeling
- Modular Python architecture

---

## Project Structure

password-security-toolkit/

├── password_toolkit.py   (Core CLI application)
├── gui_app.py            (Desktop GUI version)
└── README.md             (Project documentation)

---

## How to Run

### CLI Version

Check password strength:

py password_toolkit.py --check "YourPassword"

Check password and generate report:

py password_toolkit.py --check "YourPassword" --report

Generate a secure password:

py password_toolkit.py --generate 16

Hash a password:

py password_toolkit.py --hash "YourPassword"

Verify a hashed password:

py password_toolkit.py --verify "YourPassword" --stored "<stored_json_here>"

---

### GUI Version

Run the desktop application:

py gui_app.py

---

## Example Output (CLI)

Strength: Strong  
Score: 5  
Entropy (bits): 91.8  
Security Score (0–100): 91  

Feedback:
- Avoid common words or sequences (e.g., 'password', '1234').

---

## Educational Purpose

This project is designed for educational cybersecurity demonstration and portfolio development. It showcases applied cryptography, mathematical modeling, secure coding practices, and interface development.

---

## Author

Hamdan Ahmed  
IB Diploma Programme Student  
Interested in Computer Science, Artificial Intelligence, and Cybersecurity
