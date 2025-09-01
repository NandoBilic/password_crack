# Password Hash Cracker

A simple password cracking tool implemented in C that uses SHA-256 hashing.  
It attempts to find a plaintext password that matches a given SHA-256 hash, supporting minor variations such as character case flips and digit substitutions.

## Features
- Converts SHA-256 hashes from hex strings to raw bytes
- Verifies candidate passwords against a target SHA-256 hash
- Tries simple transformations to crack passwords:
  - Lowercase and Uppercase substitutions
  - Digit substitutions (0–9)
- Includes test functions for all core utilities (`hex_to_byte`, `hexstr_to_hash`, `check_password`, `crack_password`)
