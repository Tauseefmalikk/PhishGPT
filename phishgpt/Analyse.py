import subprocess
import json
import requests
import time
from urllib.parse import urlparse
from ml_zero_shot import classify_email_zero_shot

# ==========================
# Trusted Domain Whitelist
# ==========================
trusted_domains = ['google.com', 'accounts.google.com', 'myaccount.google.com']

def is_trusted_email(email):
    return all(
        any(domain in urlparse(link).netloc for domain in trusted_domains)
        for link in email.get('links', [])
    )

# ==========================
# VirusTotal API
# ==========================
VT_API_KEY = "your_virustotal_api_key"  # Replace with your own

def check_url_vt(url):
    headers = {"x-apikey": VT_API_KEY}
    url_id = requests.utils.quote(url, safe='')
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    resp = requests.get(vt_url, headers=headers)
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return stats["malicious"] + stats["suspicious"]
    return -1

def check_domain_vt(domain):
    headers = {"x-apikey": VT_API_KEY}
    vt_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    resp = requests.get(vt_url, headers=headers)
    if resp.status_code == 200:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return stats["malicious"] + stats["suspicious"]
    return -1

# ==========================
# LLM with Ollama
# ==========================
def ask_mistral(prompt, model="mistral"):
    result = subprocess.run(
        ["ollama", "run", model],
        input=prompt.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    return result.stdout.decode()

# ==========================
# Final Decision Logic
# ==========================
def final_verdict_fusion(email):
    llm = email.get("verdict", "Unknown").lower()
    ml = email.get("ml_verdict", "Unknown").lower()
    vt = email.get("vt_reputation", {})
    vt_threats = sum(1 for rep in vt.values() if rep["url_score"] > 0 or rep["domain_score"] > 0)

    votes = sum([
        ml == "phishing",
        llm == "phishing",
        vt_threats > 0
    ])

    if votes >= 2:
        return "Phishing"
    elif ml == "suspicious" or llm == "suspicious" or vt_threats == 1:
        return "Suspicious"
    else:
        return "Legitimate"

# ==========================
# Main Analyzer Function
# ==========================
def analyze_emails_with_llm(emails):
    for email in emails:
        # --- VirusTotal reputation check ---
        url_reputation = {}
        for url in email.get('links', []):
            domain = urlparse(url).netloc
            url_score = check_url_vt(url)
            domain_score = check_domain_vt(domain)
            url_reputation[url] = {
                "domain": domain,
                "url_score": url_score,
                "domain_score": domain_score
            }
            time.sleep(15)  # Respect VT rate limit

        email['vt_reputation'] = url_reputation

        # --- ML Classification (Zero-Shot) ---
        ml_verdict, ml_confidence = classify_email_zero_shot(email["body"])
        email["ml_verdict"] = ml_verdict
        email["ml_confidence"] = ml_confidence

        # --- LLM Prompt (Mistral) ---
        prompt = f"""
You are a cybersecurity LLM designed to detect phishing attacks in emails.

Analyze the following email and determine whether it is:
- Phishing: Tries to trick the user into clicking a link, downloading a file, or sharing sensitive info.
- Legitimate: A normal email with no signs of fraud or attack.
- Suspicious: Looks strange or has unusual elements but cannot be confirmed as phishing.

Consider the sender, subject, body, links, and VirusTotal analysis.

### EMAIL ###
From: {email['from']}
Subject: {email['subject']}
Body: {email['body']}
Links: {', '.join(email['links']) if email['links'] else 'None'}
VirusTotal: {json.dumps(url_reputation)}

Respond ONLY in this format:
Verdict: [Phishing / Legitimate / Suspicious]
Reason: [One sentence reason]
"""
        print(f"\n📩 Analyzing email from: {email['from']}")
        response = ask_mistral(prompt)

        try:
            verdict = next(line for line in response.splitlines() if "Verdict" in line).split(":", 1)[1].strip()
            reason = next(line for line in response.splitlines() if "Reason" in line).split(":", 1)[1].strip()
        except Exception:
            verdict = "Unknown"
            reason = response.strip()

        email["verdict"] = verdict
        email["verdict_reason"] = reason

        # --- Trusted Domain Override ---
        if verdict == "Phishing" and is_trusted_email(email):
            email["verdict"] = "Legitimate"
            email["verdict_reason"] += " (Corrected: all links are from trusted domains)"

        # --- Final Verdict ---
        email["final_verdict"] = final_verdict_fusion(email)

        # --- Output in Terminal ---
        print(f"🤖 ML Verdict: {ml_verdict} ({ml_confidence}%)")
        print(f"🧠 LLM Verdict: {email['verdict']} | Reason: {email['verdict_reason']}")
        print(f"🔐 Final Verdict: {email['final_verdict']}")

    return emails

# ==========================
# Run Analysis
# ==========================
if __name__ == "__main__":
    with open("email.json", "r", encoding="utf-8") as f:
        emails = json.load(f)

    results = analyze_emails_with_llm(emails)

    with open("email_phish_check_ollama.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

    print("\n📦 All results saved to email_phish_check_ollama.json")
