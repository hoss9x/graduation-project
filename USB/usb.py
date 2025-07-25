import os
import subprocess
import time
import threading
import tkinter as tk
from tkinter import messagebox
import psutil
import json
import wmi
import magic
import sqlite3

DEVICE_FILE = "usb_devices.json"
DB_FILE = "usb_logs.db"
MALICIOUS_MIME_TYPES = {"application/x-dosexec", "application/x-msdownload"}

def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            serial TEXT,
            label TEXT,
            status TEXT,
            message TEXT
        )
        """)

def log_to_db(serial, label, status, message):
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
        INSERT INTO logs (timestamp, serial, label, status, message)
        VALUES (datetime('now'), ?, ?, ?, ?)
        """, (serial, label, status, message))

def load_devices():
    if os.path.exists(DEVICE_FILE):
        try:
            with open(DEVICE_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    return json.loads(content)
        except:
            log_to_db("N/A", "N/A", "Error", "Could not load USB device list.")
    return {}

def save_devices(data):
    with open(DEVICE_FILE, "w") as f:
        json.dump(data, f, indent=4)

DEVICE_LIST = load_devices()

def get_usb_serial_and_label(drive_letter):
    try:
        letter = drive_letter.strip("\\").strip(":")
        powershell_script = f"""
        $partition = Get-Partition -DriveLetter '{letter}' -ErrorAction SilentlyContinue
        $label = (Get-Volume -DriveLetter '{letter}' -ErrorAction SilentlyContinue).FileSystemLabel
        if ($partition) {{
            $disk = ($partition | Get-Disk)
            $serial = ($disk | Get-PhysicalDisk | Select-Object -ExpandProperty SerialNumber)
            if (-not $serial) {{
                $serial = ($disk | Select-Object -ExpandProperty SerialNumber)
            }}
        }}
        "$serial|||$label"
        """
        result = subprocess.check_output(["powershell", "-Command", powershell_script], text=True).strip()
        serial, label = result.split("|||")
        if not serial or serial.lower() == "null":
            serial_wmi = get_usb_serial_wmi(drive_letter)
            if serial_wmi:
                serial = serial_wmi
        return serial.strip(), label.strip()
    except Exception as e:
        log_to_db("N/A", "N/A", "Error", f"Get serial/label failed: {e}")
        return None, None

def get_usb_serial_wmi(drive_letter):
    try:
        c = wmi.WMI()
        for physical in c.Win32_DiskDrive():
            for partition in physical.associators("Win32_DiskDriveToDiskPartition"):
                for logical in partition.associators("Win32_LogicalDiskToPartition"):
                    if logical.DeviceID.lower().startswith(drive_letter.lower()):
                        return physical.SerialNumber.strip() if physical.SerialNumber else None
    except Exception as e:
        log_to_db("N/A", "N/A", "Error", f"WMI fallback failed: {e}")
    return None

def contains_malicious_files(device):
    detected = []
    try:
        for root, _, files in os.walk(device):
            for file in files:
                file_path = os.path.join(root, file)
                if file.lower() == "autorun.inf":
                    detected.append("autorun.inf")
                    log_to_db("N/A", "N/A", "Warning", f"Autorun file detected: {file_path}")
                    continue

                if file_path.lower().endswith((".exe", ".bat", ".cmd", ".vbs", ".js")):
                    detected.append(os.path.splitext(file)[1].lower())
                    log_to_db("N/A", "N/A", "Warning", f"Executable file detected: {file_path}")
                    continue

                try:
                    mime_type = magic.from_file(file_path, mime=True)
                    print(f"[DEBUG] {file_path} → {mime_type}")
                    if mime_type in MALICIOUS_MIME_TYPES:
                        detected.append(mime_type)
                except Exception as e:
                    log_to_db("N/A", "N/A", "Error", f"File check failed: {e}")
    except Exception as e:
        log_to_db("N/A", "N/A", "Error", f"Scan failed: {e}")

    return detected



def eject_usb(drive_letter):
    try:
        powershell_script = f"""
        $app = New-Object -ComObject Shell.Application
        $drive = $app.Namespace(17).ParseName("{drive_letter}")
        if ($drive) {{
            $drive.InvokeVerb("Eject")
        }} else {{
            Write-Output "Drive object is null"
        }}
        """
        result = subprocess.check_output(["powershell", "-Command", powershell_script], text=True).strip()
        if "Drive object is null" in result:
            eject_usb_fallback(drive_letter)
        else:
            log_to_db("N/A", "N/A", "Info", f"Ejected USB {drive_letter} via Shell.")
    except Exception as e:
        log_to_db("N/A", "N/A", "Error", f"Eject Shell failed: {e}")
        eject_usb_fallback(drive_letter)

def eject_usb_fallback(drive_letter):
    try:
        volume_letter = drive_letter.strip(":").strip("\\")
        script = f"select volume {volume_letter}\nremove\n"
        with open("temp_diskpart.txt", "w") as f:
            f.write(script)
        subprocess.run(["diskpart", "/s", "temp_diskpart.txt"], check=True)
        os.remove("temp_diskpart.txt")
        log_to_db("N/A", "N/A", "Info", f"Fallback ejection used for {drive_letter}")
    except Exception as e:
        log_to_db("N/A", "N/A", "Error", f"Fallback eject failed: {e}")

def show_alert_and_eject(label, drive_letter):
    root = tk.Tk()
    root.withdraw()
    messagebox.showwarning("USB Access Blocked", f"Unauthorized USB \"{label}\" has been blocked and ejected.")
    eject_usb(drive_letter)
    root.destroy()

def prompt_user_for_usb(serial, label, drive_letter, message, color, is_placeholder=False):
    result = {"action": "block"}

    def block(): result["action"] = "block"; win.destroy()
    def allow_once(): result["action"] = "allow_once"; win.destroy()
    def allow_and_remember(): result["action"] = "allow_remember"; win.destroy()

    win = tk.Tk()
    win.title("New USB Detected")
    win.geometry("420x220")

    serial_note = " (Generated)" if is_placeholder else ""

    frame = tk.Frame(win)
    frame.pack(pady=10)

    # Flash label - always black
    tk.Label(frame, text=f"Label: {label}", font=("Arial", 12), fg="black").pack(anchor="w")

    # Serial number - always black with note if placeholder
    tk.Label(frame, text=f"Serial: {serial}{serial_note}", font=("Arial", 12), fg="black").pack(anchor="w")

    # Status message - colored based on threat/safety
    tk.Label(frame, text=f"\n{message}", font=("Arial", 12), fg=color).pack(anchor="w")


    btn_frame = tk.Frame(win)
    btn_frame.pack()

    tk.Button(btn_frame, text="\u274c Block", width=12, command=block).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="\u2705 Allow Once", width=12, command=allow_once).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text="\u2705 Allow & Remember", width=16, command=allow_and_remember).pack(side=tk.LEFT, padx=5)

    win.mainloop()
    return result["action"]

def monitor_usb():
    connected = set()
    while True:
        current_devices = {d.device for d in psutil.disk_partitions() if 'removable' in d.opts}
        new_devices = current_devices - connected

        for device in new_devices:
            drive_letter = device.strip("\\")
            serial, label = get_usb_serial_and_label(drive_letter)

            is_placeholder = False
            if not serial or serial.lower() == "null" or len(serial.strip()) < 6:
                serial = f"unknown_serial_{(label or drive_letter).replace(' ', '_')}"
                is_placeholder = True
                log_to_db(serial, label, "Warning", f"Serial number invalid/short. Using placeholder: {serial}")

            if serial in DEVICE_LIST:
                if DEVICE_LIST[serial] == "blocked":
                    show_alert_and_eject(label, drive_letter)
                    log_to_db(serial, label, "Blocked", "Previously blocked device auto-ejected.")
                    continue
                elif DEVICE_LIST[serial] == "trusted":
                    log_to_db(serial, label, "Trusted", "Previously trusted device allowed.")
                    connected.add(device)
                    continue

            file_count = sum(len(files) for _, _, files in os.walk(drive_letter))
            if file_count == 0:
                log_to_db(serial, label, "Allowed Once", "Empty USB device")
                connected.add(device)
                continue

            detected_threats = contains_malicious_files(drive_letter)

            if detected_threats:
                threat_types = ", ".join(set(detected_threats))
                usb_status = f"\u26a0\uFE0F Threats detected in USB:\n{threat_types}"
                status_color = "#8B0000"  # Dark red
            else:
                usb_status = "\u2705 No threats found in the USB."
                status_color = "green"



            action = prompt_user_for_usb(serial, label, drive_letter, usb_status, status_color, is_placeholder)

            if action == "block":
                DEVICE_LIST[serial] = "blocked"
                save_devices(DEVICE_LIST)
                show_alert_and_eject(label, drive_letter)
                log_to_db(serial, label, "Blocked", "User chose to block.")
                continue
            elif action == "allow_remember":
                DEVICE_LIST[serial] = "trusted"
                save_devices(DEVICE_LIST)
                log_to_db(serial, label, "Trusted", "User allowed and remembered.")
            elif action == "allow_once":
                log_to_db(serial, label, "Allowed Once", "User allowed once.")

            connected.add(device)

        for dev in list(connected):
            if dev not in current_devices:
                connected.remove(dev)
                log_to_db("N/A", dev, "Removed", "USB removed.")

        time.sleep(2)

if __name__ == "__main__":
    init_db()
    threading.Thread(target=monitor_usb, daemon=True).start()
    while True:
        time.sleep(1)
