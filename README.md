# Phishing URL Detector

A beginner-friendly Python cybersecurity project that analyzes URLs for suspicious signs and optionally checks them in real time using the Google Safe Browsing API.

## Features

- Checks if a URL uses HTTPS
- Detects suspicious keywords like `login`, `verify`, `account`, and `password`
- Flags URLs with `@` symbols
- Detects long URLs
- Detects many subdomains
- Gives a risk score and risk level
- Uses Google Safe Browsing API for real-time threat checking
- Supports secret API keys using `.env`

## Project Structure

```text
phishing-url-detector/
├── advance_phishing_url_detector.py
├── phishing_url_detector.py
├── requirements.txt
├── README.md
├── .env.example
└── .gitignore
