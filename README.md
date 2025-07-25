# graduation-project
# SPAM-FILTER and USB Protection System

This project is a security-focused solution that combines:
- Spam Email Detection (using both AI and Rule-Based approaches)
- USB Threat Detection (real-time flash drive inspection)

---

## Project Structure

```
SPAM-FILTER/
│
├── GUI.py             # GUI Dashboard for Email Analysis and Runs AI and Rule-based Scripts
├── spam_ai.py         # AI-based Spam Classifier using Transformers
├── spam_rules.py      # Rule-based Spam Classifier
│
USB/
├── usb.py             # USB device monitoring and malware scanning
```

---

## Requirements

The project uses the following Python libraries:

### For Email Spam Detection:
- google-api-python-client
- google-auth
- google-auth-oauthlib
- bs4
- requests
- email
- transformers
- langdetect
- spellchecker
- dotenv
- colorama
- unicodedata
- pandas
- matplotlib
- tkinter
- customtkinter

### For USB Threat Detection:
- wmi
- magic
- sqlite3
- psutil

---

## Installation

1. Clone or extract the repository.
2. Install dependencies:
```bash
pip install -r requirements.txt
```

If `requirements.txt` is missing, you can install manually using:
```bash
pip install google-api-python-client google-auth google-auth-oauthlib beautifulsoup4 requests transformers langdetect pyspellchecker python-dotenv colorama pandas matplotlib customtkinter wmi python-magic psutil
```

---

## How to Use

### 1. Email Spam Filter
- Run either:
```bash
python SPAM-FILTER/spam_ai.py        # for AI-based detection
python SPAM-FILTER/spam_rules.py     # for rule-based detection
```
- Then launch GUI:
```bash
python SPAM-FILTER/GUI.py
```

### 2. USB Threat Protection
- Run:
```bash
python USB/usb.py
```

The program will:
- Monitor USB insertions
- Check files using MIME type inspection
- Log entries into an SQLite database
- Show alert messages for suspicious content

---

## Notes
- Make sure to authenticate with Gmail via browser when prompted.
- Reports and logs will be stored under the Reports/ directory and the local database.
- Attachments are checked using VirusTotal API (if configured in `.env`).

---

## Authors
Graduation Project – Network & Information Security Engineering  
Al-Hussein Bin Talal University – 2025
