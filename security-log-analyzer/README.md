# Security Log Analyzer

A JavaScript and Node.js command-line tool that analyzes authentication
logs and identifies repeated failed login attempts.

## Features

- Reads authentication logs from a file
- Parses security events
- Counts successful logins
- Counts failed logins
- Groups failed attempts by IP address
- Identifies IP addresses with repeated failures
- Generates a security analysis report

## Technologies

- JavaScript
- Node.js
- File System (fs) module
- Command-Line Interface

## How to Run

Make sure Node.js is installed.

Run:

```bash
node logAnalyzer.js
