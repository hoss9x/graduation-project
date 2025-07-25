# Spam Filter and USB Protection System 
**Graduation Project – Spam Filtering & Malware Detection**

---

## Project Overview

This project is a security-focused solution designed to protect users from spam emails and malware threats delivered via USB storage devices. The system leverages both Artificial Intelligence (AI) and rule-based filtering techniques, and provides an interactive graphical user interface (GUI) for ease of use and control.

---

## Key Features

- **Email Spam Filtering:**  
  - AI-powered filtering using state-of-the-art Transformers
  - Customizable rule-based spam detection
  - Attachment analysis with VirusTotal API
  - Detailed reports and activity logs

- **USB Malware Protection:**  
  - Real-time monitoring of all connected USB storage devices
  - File analysis to detect malicious files or suspicious extensions
  - Instant alerts and notifications for users
  - Logging of all events in a local SQLite database

- **Interactive GUI:**  
  - Modern dark mode theme
  - Displays filtering statistics and email history
  - Simple controls to switch between AI and Rule-Based filtering

---

## Screenshots

> **<img width="1363" height="759" alt="لقطة شاشة 2025-06-01 055835" src="https://github.com/user-attachments/assets/d01e06a4-5a56-4e92-b36c-cdb488183b12" /><img width="415" height="250" alt="لقطة شاشة 2025-06-16 193948" src="https://github.com/user-attachments/assets/6c7e801e-ee53-4c4a-b6b0-b2f9ef9f0251" />
<img width="414" height="245" alt="لقطة شاشة 2025-06-16 193928" src="https://github.com/user-attachments/assets/a67bb756-6450-4233-a171-fa83116768f2" />
<img width="1362" height="763" alt="لقطة شاشة 2025-06-09 153840" src="https://github.com/user-attachments/assets/9c0feebe-05f5-4938-814a-324fbd978caf" />
<img width="1364" height="766" alt="لقطة شاشة 2025-06-01 062636" src="https://github.com/user-attachments/assets/a8a131c2-c24e-4a26-89b8-ff04bfb6fd14" />
<img width="1360" height="758" alt="لقطة شاشة 2025-06-01 061051" src="https://github.com/user-attachments/assets/55135488-aa7b-4415-9961-4887f7cfc2c3" />
<img width="1359" height="760" alt="لقطة شاشة 2025-06-01 060430" src="https://github.com/user-attachments/assets/70f338f8-de63-4d2c-9d7a-86683c1b7d4c" />
**  
> (e.g., main dashboard, detection alerts, scan reports)  
> You can upload images in the `assets/` folder or directly in the repo.

---

## Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/hoss9x/graduation-project.git
    ```
2. **Navigate to the project directory and install dependencies:**
    ```bash
    cd graduation-project
    pip install -r requirements.txt
    ```
   If `requirements.txt` is missing, you can install manually:
    ```bash
    pip install google-api-python-client google-auth google-auth-oauthlib beautifulsoup4 requests transformers langdetect pyspellchecker python-dotenv colorama pandas matplotlib customtkinter wmi python-magic psutil
    ```

3. **Add Credentials:**
   - Place your Google API credentials in the `Credentials/` folder.
   - Create a `.env` file and add your VirusTotal API keys if you want to enable attachment scanning.

---

## Usage

### Email Spam Filtering
- To run AI-based spam filtering:
    ```bash
    python "Spam Filter/spam_ai.py"
    ```
- To run rule-based spam filtering:
    ```bash
    python "Spam Filter/spam_rules.py"
    ```
- To launch the GUI dashboard:
    ```bash
    python "Spam Filter/GUI.py"
    ```

### USB Protection
- To start the USB protection system:
    ```bash
    python USB/usb.py
    ```

**Notes:**
- On first run, you will be prompted to authenticate with Gmail and grant necessary permissions.
- All reports and logs are stored in the `Reports/` directory and a local database.

---

## Project Structure

```
graduation-project/
│
├── Spam Filter/
│   ├── GUI.py
│   ├── spam_ai.py
│   └── spam_rules.py
│
├── USB/
│   └── usb.py
│
├── Reports/
├── Credentials/
├── README.md
└── requirements.txt
```

---

## Requirements

- Python 3.8 or newer
- Internet connection (for Gmail and VirusTotal scanning)
- Windows OS (for USB protection)
- Active Gmail account

---

## Future Improvements

- USB protection support for Linux and MacOS
- Additional email provider support (Outlook, Yahoo, etc.)
- Centralized web dashboard
- Automated email reports

---

## Author

**Hussein Ali Bani Khaled**  
Graduation Project – Network & Information Security Engineering  
Al-Hussein Bin Talal University – 2025

---

## License

> You can specify the license type here (MIT, GPL, etc.)

---

**Feel free to open an Issue for suggestions or bug reports!**
