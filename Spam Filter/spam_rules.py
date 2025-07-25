import os
import time
import json
import base64
import re
import requests
import urllib.request
import datetime
from email import message_from_bytes
from email.policy import default
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from spellchecker import SpellChecker
from dotenv import load_dotenv
from langdetect import detect_langs
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
from email.mime.text import MIMEText
import unicodedata

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/contacts.readonly"
]
CREDENTIALS_FILE = "Credentials/credentials.json"
TOKEN_FILE = "Credentials/token.json"
CACHE_FILE = "spam_rules_cache.json"
ATTACHMENTS_DIR = "attachments"
REPORTS_DIR = "Reports"
USERDATA_DIR = "UsersData"
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024
SPAM_THRESHOLD = 10
SUSPICIOUS_THRESHOLD = 6
VT_SCAN_DELAY = 5
VT_MAX_RETRIES = 10
EMAIL_DELAY = 5
ATTACHMENTS_RESULTS_DIR = "attachments_results"
os.makedirs(ATTACHMENTS_RESULTS_DIR, exist_ok=True)
AI_TO_RULES_SYNC_FILE = os.path.join(USERDATA_DIR, "ai_to_rules_sync.json")
RULES_TO_AI_SYNC_FILE = os.path.join(USERDATA_DIR, "rules_to_ai_sync.json")


load_dotenv("keys.env")
VIRUSTOTAL_API_KEYS = [
    os.getenv("VIRUSTOTAL_API_KEY_1"),
    os.getenv("VIRUSTOTAL_API_KEY_2"),
]
api_key_index = 0

init(autoreset=True)

def process_ai_sync(stats):
    
    if not os.path.exists(AI_TO_RULES_SYNC_FILE):
        return

    try:
        with open(AI_TO_RULES_SYNC_FILE, "r", encoding="utf-8") as f:
            sync_data = json.load(f)

        for email, count in sync_data.items():
            stats["high_risk_counts"][email] = stats["high_risk_counts"].get(email, 0) + count

       
        with open(AI_TO_RULES_SYNC_FILE, "w") as f:
            json.dump({}, f)

    except Exception as e:
        print(Fore.RED + f"[!] Failed to process AI sync file: {e}")

def gmail_login():
    from google.oauth2.credentials import Credentials
    if os.path.exists(TOKEN_FILE):
        creds_data = json.load(open(TOKEN_FILE))
        creds = Credentials.from_authorized_user_info(info=creds_data, scopes=SCOPES)
    else:
        flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
        creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, "w") as f:
            f.write(creds.to_json())
    service = build("gmail", "v1", credentials=creds)
    profile = service.users().getProfile(userId='me').execute()
    user_email = profile['emailAddress']
    return service, user_email

def load_cache():
    return json.load(open(CACHE_FILE)) if os.path.exists(CACHE_FILE) else {}

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)

def load_contacts(user_email):
    from google.oauth2.credentials import Credentials
    contacts_path = os.path.join("UsersData", user_email, "contacts.json")
    
    if os.path.exists(contacts_path):
        return set(json.load(open(contacts_path)))

    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    people_service = build('people', 'v1', credentials=creds)

    results = people_service.people().connections().list(
        resourceName='people/me',
        personFields='emailAddresses',
        pageSize=500
    ).execute()

    emails = []
    for person in results.get("connections", []):
        for email in person.get("emailAddresses", []):
            emails.append(email.get("value").lower())

    os.makedirs(os.path.join("UsersData", user_email), exist_ok=True)
    with open(contacts_path, "w") as f:
        json.dump(emails, f, indent=2)

    return set(emails)

def save_spam_stats(user_email, stats):
    path = os.path.join(USERDATA_DIR, user_email, "spam_stats.json")
    with open(path, "w") as f:
        json.dump(stats, f, indent=2)

def load_spam_stats(user_email):
    path = os.path.join(USERDATA_DIR, user_email, "spam_stats.json")
    if not os.path.exists(path):
        return {"last_reset": datetime.datetime.now().strftime("%Y-%m"), "high_risk_counts": {}, "blacklist": []}
    return json.load(open(path))

def save_spam_stats(user_email, stats):
    path = os.path.join(USERDATA_DIR, user_email, "spam_stats.json")
    with open(path, "w") as f:
        json.dump(stats, f, indent=2)

def sanitize_filename(filename):
    filename = filename.replace("../", "").replace("..\\", "")
    invalid_chars = '<>:"/\\|?*'
    return "".join(c if c not in invalid_chars else "_" for c in filename)

def get_email_body(message):
    payload = message.get("payload", {})
    stack = [payload]
    while stack:
        part = stack.pop()
        if part.get("mimeType", "").startswith("text/"):
            data = part.get("body", {}).get("data")
            if data:
                return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")
        stack.extend(part.get("parts", []))
    return ""
def upload_to_virustotal(file_data, filename):
    global api_key_index
    api_key = VIRUSTOTAL_API_KEYS[api_key_index]
    api_key_index = (api_key_index + 1) % len(VIRUSTOTAL_API_KEYS)

    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}
    files = {"file": (filename, file_data)}
    response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        return wait_for_vt_analysis(analysis_id)
    else:
        print(f"[❌] VirusTotal upload failed: {response.text}")
        return None


def wait_for_vt_analysis(analysis_id):
    global api_key_index
    for _ in range(VT_MAX_RETRIES):
        api_key = VIRUSTOTAL_API_KEYS[api_key_index]
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analysis = response.json()
            status = analysis['data']['attributes']['status']
            if status == 'completed':
                stats = analysis['data']['attributes']['stats']
                return stats['malicious'] >= 1
        time.sleep(VT_SCAN_DELAY)
    print("[!] VT analysis timeout or error.")
    return None

def expand_url(short_url):
    try:
        response = urllib.request.urlopen(short_url)
        return response.geturl()
    except:
        return short_url

def scan_attachments_and_save(service, message_id, email_id):
    from base64 import urlsafe_b64decode
    attachment_results = []
    try:
        msg = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        payload = msg.get('payload', {})

        def process_parts(parts):
            for part in parts:
                filename = part.get("filename")
                body = part.get("body", {})
                attachment_id = body.get("attachmentId")
                if filename and attachment_id:
                    attachment = service.users().messages().attachments().get(
                        userId='me', messageId=message_id, id=attachment_id
                    ).execute()
                    file_data = urlsafe_b64decode(attachment['data'].encode('UTF-8'))
                    if len(file_data) <= MAX_ATTACHMENT_SIZE:
                        is_malicious = upload_to_virustotal(file_data, filename)
                        attachment_results.append({
                            "filename": filename,
                            "malicious": is_malicious
                        })
                    else:
                        attachment_results.append({
                            "filename": filename,
                            "error": "File too large to scan"
                        })
                if "parts" in part:
                    process_parts(part["parts"])

        if "parts" in payload:
            process_parts(payload["parts"])

    except Exception as e:
        print(f"[!] Attachment scan error: {e}")
        attachment_results.append({"error": str(e)})

    results_path = os.path.join(ATTACHMENTS_RESULTS_DIR, f"{email_id}.json")
    with open(results_path, "w", encoding="utf-8") as f:
        json.dump(attachment_results, f, indent=2, ensure_ascii=False)

    return attachment_results


def analyze_email(sender, subject, body, headers, attachments_results):
    
    score = 0
    reasons = []

    groups = {
        "identity_mismatch": 0,
        "phishing_indicators": 0,
        "malware_threat": 0,
        "text_quality": 0,
        "link_abuse": 0
    }

    

    if subject.isupper():
        score += 2
        groups["text_quality"] += 1
        reasons.append("Subject in all caps")

    if len(subject) < 5:
        score += 2
        groups["text_quality"] += 1
        reasons.append("Very short subject")

    urgency_words = ["urgent", "act now", "important", "final warning", "limited offer",
                     "exclusive", "winner", "alert", "verify", "account suspended", "claim now"]
    if any(word in body.lower() for word in urgency_words):
        score += 1
        groups["phishing_indicators"] += 1
        reasons.append("Urgency language detected")

    urls = re.findall(r'https?://\S+', body)
    if any(domain in url for domain in ["bit.ly", "goo.gl", "tinyurl.com"] for url in urls):
        score += 3
        groups["link_abuse"] += 1
        reasons.append("Suspicious shortened link detected")

    if len(urls) > 10:
        score += 1
        groups["link_abuse"] += 1
        reasons.append("Too many links")

    risky_extensions = [".exe", ".js", ".scr", ".bat", ".vbs"]
    for file_path in [r['file'] for r in attachments_results if 'file' in r]:
        if any(file_path.lower().endswith(ext) for ext in risky_extensions):
            score += 5
            groups["malware_threat"] += 1
            reasons.append(f"Risky attachment extension: {file_path}")

    dkim_dmarc_found = any("dkim=" in h.get("value", "").lower() or "dmarc=" in h.get("value", "").lower() for h in headers if h.get("name") == "Authentication-Results")
    dkim_dmarc_fail = any(fail in h.get("value", "").lower() for h in headers if h.get("name") == "Authentication-Results" for fail in ["spf=fail", "dkim=fail", "dmarc=fail"])

    if dkim_dmarc_fail:
        score += 5
        groups["identity_mismatch"] += 1
        reasons.append("Authentication failed (SPF/DKIM/DMARC)")
    elif not dkim_dmarc_found:
        score += 3
        groups["identity_mismatch"] += 1
        reasons.append("Missing DKIM/DMARC signature")


    if "<script>" in body.lower() or "<iframe" in body.lower():
        score += 4
        groups["phishing_indicators"] += 1
        reasons.append("Suspicious HTML elements detected")


    spell = SpellChecker()
    words = re.findall(r'\b\w+\b', body)
    filtered_words = [w for w in words if w.isalpha() and len(w) > 5]
    unknown_words = spell.unknown(filtered_words)
    
    if len(words) < 30:
        score += 2
        groups["text_quality"] += 1
        reasons.append("Very short email body")

    for r in attachments_results:
        if r.get("malicious", 0) >= 1:
            score += 6
            groups["malware_threat"] += 1
            reasons.append("Malicious attachment detected")

    

    try:
        import phonenumbers
        numbers = re.findall(r'\+?\d[\d\s\-]{7,}\d', body)
        for number in numbers:
            try:
                parsed = phonenumbers.parse(number, None)
                region = phonenumbers.region_code_for_number(parsed)
                if region and region not in ['SA', 'AE', 'JO', 'EG']:
                    score += 3
                    groups["identity_mismatch"] += 1
                    reasons.append("Sender claims local origin but uses foreign number")
                    break
            except:
                continue
    except ImportError:
        pass

    if "@" in sender:
        name_part = sender.split("@")[0].lower()
        if name_part not in sender.lower():
            score += 4
            groups["identity_mismatch"] += 1
            reasons.append("Display name and domain mismatch")

    if "<img" in body.lower() and len(re.findall(r'\w+', body)) < 10:
        score += 3
        groups["phishing_indicators"] += 1
        reasons.append("Image-only content with no body text")

    try:
        langs = detect_langs(body)
        main_lang = langs[0].lang if langs else ""
        if main_lang not in ['en', 'ar']:
            score += 4
            groups["text_quality"] += 1
            reasons.append("Unexpected language usage (possible spoofing)")
    except:
        pass

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body, "html.parser")
        for a in soup.find_all("a", href=True):
            if a.text.strip() and a['href'] and a.text.strip() not in a['href']:
                score += 3
                groups["link_abuse"] += 1
                reasons.append("Link text does not match actual URL")
                break
    except:
        pass

    try:
        import unicodedata
        odd_chars = [c for c in body if ord(c) > 127]
        for char in odd_chars:
            name = unicodedata.name(char, "")
            if any(x in name for x in ["CYRILLIC", "DEVANAGARI", "ARABIC"]) and "LATIN" not in name:
                score += 2
                groups["phishing_indicators"] += 1
                reasons.append("Suspicious unicode characters (spoofing attempt)")
                break
    except:
        pass

    reply_to = next((h['value'] for h in headers if h['name'].lower() == 'reply-to'), "")
    if reply_to and "@" in reply_to and reply_to.split('@')[-1] != sender.split('@')[-1]:
        score += 5
        groups["identity_mismatch"] += 1
        reasons.append("Reply-To domain mismatch")

    phishing_phrases = ["click here", "verify", "account", "reset", "login"]
    phrase_count = sum(body.lower().count(p) for p in phishing_phrases)
    if phrase_count > 5:
        score += 2
        groups["phishing_indicators"] += 1
        reasons.append("Repeated phishing phrases")

    

    if groups["malware_threat"] >= 1:
        score += 5
        reasons.append("Malware indicators elevated threat")

    if groups["phishing_indicators"] >= 2 and groups["identity_mismatch"] >= 1:
        score += 5
        reasons.append("Combined phishing and identity mismatch")

    return score, reasons

def classify_score(score):
    if score >= 35:
        return "High Risk (Spam)"
    elif score >= 22:
        return "Likely Spam"
    elif score >= 12:
        return "Suspicious"
    else:
        return "Safe"

def send_warning_email(service, to_email, original_subject):
    warning_subject = f"⚠️ Security Notice: Your Email Was Flagged"
    warning_body = f"""
    Dear Sender,

    This is an automated notification from the recipient's mail security system.

    Your email with subject: "{original_subject}" was flagged as potentially harmful or spam by our system. 

    If you believe this was a mistake, please ensure that:
    - Your sender domain matches your identity.
    - No suspicious links or attachments are included.
    - Your message complies with common security and privacy guidelines.

    Repeated offenses may result in permanent blacklisting.

    Thank you for your understanding.

    - Automated Security System
    """

    message = MIMEText(warning_body)
    message['to'] = to_email
    message['subject'] = warning_subject
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()

    try:
        service.users().messages().send(userId="me", body={"raw": raw_message}).execute()
        print(Fore.CYAN + f"[✓] Warning email sent to: {to_email}")
    except Exception as e:
        print(Fore.RED + f"[✗] Failed to send warning email to {to_email}: {e}")

def fetch_emails():
    service, user_email = gmail_login()
    cache = load_cache()
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    reports_today_dir = os.path.join(REPORTS_DIR, "Rules", today)
    os.makedirs(reports_today_dir, exist_ok=True)

    
    contacts = load_contacts(user_email)

    
    stats = load_spam_stats(user_email)

   
    current_month = datetime.datetime.now().strftime("%Y-%m")
    if stats.get("last_reset") != current_month:
        stats["last_reset"] = current_month
        stats["high_risk_counts"] = {}

    
    process_ai_sync(stats)

    
    query_params = {
    'userId': 'me',
    'labelIds': ['INBOX'],  
    'maxResults': 100
    }

    messages = []

    while True:
        results = service.users().messages().list(**query_params).execute()
        messages.extend(results.get('messages', []))
        if 'nextPageToken' in results:
            query_params['pageToken'] = results['nextPageToken']
        else:
            break

    for msg in messages:
        try:
            msg_id = msg['id']
            message = service.users().messages().get(userId='me', id=msg_id).execute()
            service.users().messages().modify(userId='me', id=msg_id, body={"removeLabelIds": ["UNREAD"]}).execute()

            headers = message['payload']['headers']
            body = get_email_body(message)

            sender_raw = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown")
            match = re.search(r'<(.+?)>', sender_raw)
            sender = match.group(1).lower() if match else sender_raw.lower()
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
            raw_email_id = subject
            email_id = re.sub(r'[<>:\"/\\\\|?*]', '_', raw_email_id)[:150]


            if email_id in cache:
                continue

            attachments_results = scan_attachments_and_save(service, message["id"], email_id)
            spam_score, reasons = analyze_email(sender, subject, body, headers, attachments_results)
            label = classify_score(spam_score)

            sender_match = re.findall(r'<(.+?)>', sender)
            if sender_match:
                sender = sender_match[0].lower()
            else:
                sender = sender.lower()



            
            if sender in stats["blacklist"]:
                label = "High Risk (Spam)"
                spam_score = 999
                reasons.append("Sender is blacklisted")

            elif label == "High Risk (Spam)":
                if sender in contacts:
                    count = stats["high_risk_counts"].get(sender, 0) + 1
                    stats["high_risk_counts"][sender] = count
                    reasons.append(f"Sender has sent {count} high-risk emails this month.")

                    if count >= 3 and sender not in stats["blacklist"]:
                        stats["blacklist"].append(sender)
                        reasons.append("Sender added to blacklist after 3 high-risk emails.")

                        
                        sync_data = {}
                        if os.path.exists(RULES_TO_AI_SYNC_FILE):
                            with open(RULES_TO_AI_SYNC_FILE, "r", encoding="utf-8") as f:
                                sync_data = json.load(f)
                        sync_data[sender] = sync_data.get(sender, 0) + 1
                        with open(RULES_TO_AI_SYNC_FILE, "w", encoding="utf-8") as f:
                            json.dump(sync_data, f, indent=2, ensure_ascii=False)
                    else:
                        send_warning_email(service, sender, subject)
                else:
                    stats["blacklist"].append(sender)
                    reasons.append("Sender added to blacklist immediately (not in contacts)")


            if spam_score >= SUSPICIOUS_THRESHOLD:
                color = Fore.RED if spam_score >= SPAM_THRESHOLD else Fore.YELLOW
                print(color + f"\n📧 From: {sender}\n📝 Subject: {subject}\n🚨 SPAM Score: {spam_score} → 🏷️ {label}")
                for reason in reasons:
                    print("   - " + reason)
                print("-" * 50)

                cache[email_id] = {
                    "from": sender,
                    "subject": subject,
                    "spam_score": spam_score,
                    "label": label,
                    "reasons": reasons,
                    "attachments": attachments_results,
                    "source": "Rules Based"
                }

                save_cache(cache)
                save_spam_stats(user_email, stats)
                cache[email_id]["id"] = email_id

                with open(os.path.join(reports_today_dir, f"{email_id}.json"), "w", encoding="utf-8") as report_file:
                    json.dump(cache[email_id], report_file, indent=2, ensure_ascii=False)

            time.sleep(EMAIL_DELAY)

        except Exception as e:
            print(f"❌ Error processing message {msg.get('id')}: {e}")

    print(Fore.GREEN + "[🏁] All messages processed.")


if __name__ == "__main__":
    fetch_emails()
