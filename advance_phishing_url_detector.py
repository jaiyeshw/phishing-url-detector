import requests
import os
from dotenv import load_dotenv

load_dotenv()

def check_google_safe_browsing(url):
    api_key = os.getenv("SAFE_BROWSING_API_KEY")

    if not api_key:
        return "API KEY MISSING", []
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"

    payload = {
        "client":{
            "clientId": "phishing-url-detector",
            "clientVersion": "1.0"

        },

        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    response = requests.post(endpoint, json= payload )
    data = response.json()

    if "matches" in data:
        threats = [match["threatType"] for match in data["matches"]]
        return "Unsafe", threats

    return "No known threat found", []


from urllib.parse import urlparse

url = input("Enter a URL to scan: ")

parsed_url = urlparse(url)
domain = parsed_url.netloc
path = parsed_url.path

risk_score = 0
reasons = []
suspicious_keywords = ["login", "verify", "account", "secure", "update", "banking", "password"]

api_result, threats = check_google_safe_browsing(url)



print("API result:", api_result)

if threats:
    print("Threats found:")
    for threat in threats:
        print("-", threat)

for keyword in suspicious_keywords:
    if keyword in url.lower():
        risk_score += 1
        reasons.append(f"URL contains suspicious keyword: {keyword}")

if parsed_url.scheme != "https":
    risk_score += 2
    reasons.append("URL does not use HTTPS. IT MAY OR MAY NOT BE SECURE ENOUGH")

if "@" in url:
    risk_score += 2
    reasons.append("URL contains '@', which can hide the real destination.")

if len(url) > 75:
    risk_score += 1
    reasons.append("URL is unusually long.")

if domain.count(".") >= 3:
    risk_score += 1
    reasons.append("URL has many subdomains.")

print("Risk score:", risk_score)

if reasons:
    print("Reasons:")
    for reason in reasons:
        print("-", reason)
else:
    print("No obvious suspicious signs found.")

if risk_score <= 1:
    risk_level = "Low"
elif risk_score <= 3:
    risk_level = "Medium"
else:
    risk_level = "High"

print("Risk level:", risk_level)           
