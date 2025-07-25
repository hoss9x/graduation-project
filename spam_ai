import os
import base64
import email.utils
import time
import json
import requests
import re
import datetime
from email import message_from_bytes
from email.policy import default
from urllib.parse import urlparse
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from transformers import pipeline
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from email.mime.text import MIMEText


SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/contacts.readonly"
]
CREDENTIALS_FILE = 'Credentials/credentials.json'
TOKEN_FILE = 'Credentials/token.json'
MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25MB
LOG_FILE = 'scan_report.txt'
ATTACHMENTS_RESULTS_DIR = "attachments_results"
CACHE_FILE = "spam_ai_cache.json"
REPORTS_DIR = "Reports"
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(ATTACHMENTS_RESULTS_DIR, exist_ok=True)
RULES_TO_AI_SYNC_FILE = os.path.join("UsersData", "rules_to_ai_sync.json")

load_dotenv("Credentials/keys.env")
VT_API_KEYS = [
    os.getenv("VIRUSTOTAL_API_KEY_1"),
    os.getenv("VIRUSTOTAL_API_KEY_2")
]
api_key_index = 0


classifier = pipeline(
    "zero-shot-classification",
    model="facebook/bart-large-mnli",
    device=-1  # = CPU. Use 0 if you want GPU.
)

def process_rules_sync(stats):
    
    if not os.path.exists(RULES_TO_AI_SYNC_FILE):
        return

    try:
        with open(RULES_TO_AI_SYNC_FILE, "r", encoding="utf-8") as f:
            sync_data = json.load(f)

        for email, count in sync_data.items():
            stats["high_risk_counts"][email] = stats["high_risk_counts"].get(email, 0) + count

        
        with open(RULES_TO_AI_SYNC_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f)

    except Exception as e:
        print(f"[!] Failed to process rules sync file: {e}")


def load_ai_stats(user_email):
    AI_STATS_FILE = os.path.join("UsersData", user_email, "ai_spam_stats.json")
    path = os.path.join("UsersData", user_email, "ai_spam_stats.json")
    if not os.path.exists(path):
        return {
            "last_reset": datetime.datetime.now().strftime("%Y-%m"),
            "high_risk_counts": {},
            "blacklist": []
        }
    return json.load(open(path))

def save_ai_stats(user_email, stats):
    path = os.path.join("UsersData", user_email, "ai_spam_stats.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

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
        print(f"[✓] Warning email sent to: {to_email}")
    except Exception as e:
        print(f"[✗] Failed to send warning email to {to_email}: {e}")



def gmail_login():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)
    profile = service.users().getProfile(userId='me').execute()
    user_email = profile['emailAddress']
    return service, user_email
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
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    return {}


def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)


def predict_spam(text):
    result = classifier(
        text[:512],
        candidate_labels=["spam", "not spam"],
        multi_label=False
    )

   
    spam_score = 0.0
    for label, score in zip(result['labels'], result['scores']):
        if label.lower() == "spam":
            spam_score = score
            break

    
    if spam_score >= 0.90:
        return "high risk", spam_score
    elif spam_score >= 0.75:
        return "spam", spam_score
    elif spam_score >= 0.50:
        return "suspicious", spam_score
    else:
        return "safe", spam_score


def upload_to_virustotal(file_data, filename):
    global api_key_index
    api_key = VT_API_KEYS[api_key_index]
    api_key_index = (api_key_index + 1) % len(VT_API_KEYS)

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
    while True:
        api_key = VT_API_KEYS[api_key_index]
        headers = {"x-apikey": api_key}
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            analysis = response.json()
            status = analysis['data']['attributes']['status']
            if status == 'completed':
                stats = analysis['data']['attributes']['stats']
                return stats['malicious'] >= 1
            else:
                time.sleep(3)
        else:
            print(f"[❌] Error getting VT analysis: {response.text}")
            return None

def extract_email_body(mime_msg):
    if mime_msg.is_multipart():
        for part in mime_msg.walk():
            ctype = part.get_content_type()
            if ctype == 'text/plain':
                return part.get_payload(decode=True).decode(errors='ignore')
            elif ctype == 'text/html':
                html = part.get_payload(decode=True).decode(errors='ignore')
                soup = BeautifulSoup(html, "html.parser")
                return soup.get_text(separator="\n")
    else:
        if mime_msg.get_content_type() == 'text/html':
            html = mime_msg.get_payload(decode=True).decode(errors='ignore')
            soup = BeautifulSoup(html, "html.parser")
            return soup.get_text(separator="\n")
        else:
            return mime_msg.get_payload(decode=True).decode(errors='ignore')
    return ""


def extract_links(text):
    url_pattern = re.compile(r'(https?://[^\s]+)')
    return url_pattern.findall(text)


def check_links(links):
    for link in links:
        try:
            response = requests.get(link, timeout=5)
            if response.status_code == 200:
                parsed = urlparse(link)
                if parsed.netloc:
                    dummy_file = link.encode()
                    if upload_to_virustotal(dummy_file, parsed.netloc):
                        return True
        except:
            continue
    return False


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
def sync_to_rules(sender_email):
    sync_file = os.path.join("UsersData", "ai_to_rules_sync.json")
    sync_data = {}

    
    if os.path.exists(sync_file):
        try:
            with open(sync_file, "r", encoding="utf-8") as f:
                sync_data = json.load(f)
        except:
            sync_data = {}

    
    sync_data[sender_email] = sync_data.get(sender_email, 0) + 1

    
    with open(sync_file, "w", encoding="utf-8") as f:
        json.dump(sync_data, f, indent=2, ensure_ascii=False)



def process_message(service, message, cache, user_email, contacts):
    msg = service.users().messages().get(userId='me', id=message['id'], format='raw').execute()
    msg_raw = base64.urlsafe_b64decode(msg['raw'].encode('ASCII'))
    mime_msg = message_from_bytes(msg_raw, policy=default)

    sender = mime_msg['From']
    subject = mime_msg["Subject"] or "NoSubject"
    email_id = re.sub(r'[<>:\"/\\\\|?*]', '_', subject)[:150]

   
    if email_id in cache:
        print(f"[⚠️] Skipping already processed email: {email_id}")
        return

   
    email_body = extract_email_body(mime_msg)
    spam_level, score = predict_spam(email_body)
    links = extract_links(email_body)
    has_malicious_link = False
    attachments_result = scan_attachments_and_save(service, message['id'], email_id)
    has_malicious_attachment = any(item.get("malicious") for item in attachments_result)

    final_spam_decision = spam_level in ["spam", "high risk"] or has_malicious_attachment or has_malicious_link

   
    report = "\n🔍 Email Spam Detection Report\n"
    report += f"📩 Sender: `{sender}`\n"
    report += f"⚠ Classification Level: `{spam_level}`\n"
    report += f"📊 Confidence Score: `{score:.2f}`\n"
    report += f"🌐 Malicious Link Detected: `{has_malicious_link}`\n"
    report += f"📎 Malicious Attachment Detected: `{has_malicious_attachment}`\n"
    report += "------------------------------\n"

    if final_spam_decision:
        report += "🚨 **This email is considered SPAM!** 🚨\n"
        service.users().messages().modify(userId='me', id=message['id'], body={'addLabelIds': ['SPAM']}).execute()

       
        try:
            from_email = re.search(r'<(.+?)>', sender)
            sender_email = from_email.group(1) if from_email else sender
            sender_email = sender_email.lower().strip()
        except Exception as e:
            print(f"[!] Failed to extract sender email for warning: {e}")
            sender_email = sender.lower().strip()

        stats = load_ai_stats(user_email)
        current_month = datetime.datetime.now().strftime("%Y-%m")
        if stats.get("last_reset") != current_month:
            stats["last_reset"] = current_month
            stats["high_risk_counts"] = {}

        if spam_level == "high risk":
            if sender_email not in stats["blacklist"]:
                stats["blacklist"].append(sender_email)
                sync_to_rules(sender_email)
                print(f"[✓] Blacklisted immediately due to HIGH RISK: {sender_email}")
        else:
            count = stats["high_risk_counts"].get(sender_email, 0) + 1
            stats["high_risk_counts"][sender_email] = count

            if sender_email in contacts:
                send_warning_email(service, sender_email, subject)
                if count >= 3 and sender_email not in stats["blacklist"]:
                    stats["blacklist"].append(sender_email)
                    sync_to_rules(sender_email)
            else:
                if sender_email not in stats["blacklist"]:
                    stats["blacklist"].append(sender_email)
                    sync_to_rules(sender_email)

        save_ai_stats(user_email, stats)
    else:
        report += "✅ **This email is considered SAFE.** ✅\n"

    
    service.users().messages().modify(userId='me', id=message['id'], body={'removeLabelIds': ['UNREAD']}).execute()

   
    cache[email_id] = {
        "from": sender,
        "subject": subject,
        "score": score,
        "spam_level": spam_level,
        "malicious_link": has_malicious_link,
        "malicious_attachment": has_malicious_attachment,
        "source": "spam_ai"
    }
    save_cache(cache)

   
    append_daily_ai_report(
        email_id=email_id,
        sender=sender,
        subject=subject,
        score=score,
        spam_level=spam_level,
        has_malicious_link=has_malicious_link,
        has_malicious_attachment=has_malicious_attachment,
        attachments_result=attachments_result
    )

    
    print(report)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(report + "\n" + "=" * 60 + "\n")


def append_daily_ai_report(email_id, sender, subject, score, spam_level, has_malicious_link, has_malicious_attachment, attachments_result):
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    reports_today_dir = os.path.join(REPORTS_DIR, "AI", today)
    os.makedirs(reports_today_dir, exist_ok=True)

    entry = {
        "id": email_id,
        "from": sender,
        "subject": subject,
        "spam_score": score,
        "label": spam_level,
        "malicious_link": has_malicious_link,
        "malicious_attachment": has_malicious_attachment,
        "attachments": attachments_result,
        "source": "AI Based"
    }

    report_path = os.path.join(reports_today_dir, f"{email_id}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(entry, f, indent=2, ensure_ascii=False)




def fetch_emails():
    service, user_email = gmail_login()
    cache = load_cache()
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    reports_today_dir = os.path.join(REPORTS_DIR,"AI", today)
    os.makedirs(reports_today_dir, exist_ok=True)

    
    contacts = load_contacts(user_email)

   
    stats = load_ai_stats(user_email)

    
    current_month = datetime.datetime.now().strftime("%Y-%m")
    if stats.get("last_reset") != current_month:
        stats["last_reset"] = current_month
        stats["high_risk_counts"] = {}

   
    process_rules_sync(stats)
    save_ai_stats(user_email, stats)

    query_params = {
    'userId': 'me',
    'labelIds': ['INBOX'], 
    'maxResults': 50
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
            process_message(service, msg, cache, user_email, contacts)
        except Exception as e:
            print(f"[!] Error processing message {msg.get('id')}: {e}")

    print("[✓] All messages processed.")


if __name__ == "__main__":
    fetch_emails()
