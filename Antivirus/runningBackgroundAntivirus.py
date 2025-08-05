import os
import requests
import time
import tkinter as tk
from tkinter import filedialog, scrolledtext
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading

virus_total_api_key = "a334f3c7ae716951831d623277ab0f71b0310407ae8987fae75a0f4b4cb07683"

def upload_file(file_path):
    url = "https://www.virustotal.com/vtapi/v2/file/scan"
    params = {"apikey": virus_total_api_key}
    with open(file_path, 'rb') as f:
        files = {'file': (os.path.basename(file_path), f)}
        response = requests.post(url, files=files, params=params)
    return response.json()

def get_report(scan_id, log_output):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {'apikey': virus_total_api_key, 'resource': scan_id}

    while True:
        response = requests.get(url, params=params)
        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 1:
                positives = result.get("positives", 0)
                total = result.get("total", 0)
                log_output.insert(tk.END, f"Detected: {positives}/{total}\n")
                return positives > 0
            else:
                log_output.insert(tk.END, "Waiting for scan result...\n")
        elif response.status_code == 204:
            log_output.insert(tk.END, "API limit reached. Waiting...\n")
        else:
            log_output.insert(tk.END, f"Unexpected response: {response.status_code}\n")
            return False
        log_output.update()
        time.sleep(5)

def scan_file(file_path, log_output):
    log_output.insert(tk.END, f"🔍 Scanning: {file_path}\n")
    log_output.update()

    response = upload_file(file_path)
    scan_id = response.get('scan_id')
    if scan_id:
        is_virus = get_report(scan_id, log_output)
        if is_virus:
            log_output.insert(tk.END, f"⚠️ VIRUS DETECTED: {file_path}\n\n")
        else:
            log_output.insert(tk.END, f"✅ Clean: {file_path}\n\n")
    else:
        log_output.insert(tk.END, f"❌ Error uploading file: {file_path}\n\n")
    log_output.update()

def iterate_files(folder_path, log_output):
    for filename in os.listdir(folder_path):
        full_path = os.path.join(folder_path, filename)
        if os.path.isdir(full_path):
            iterate_files(full_path, log_output)
        else:
            scan_file(full_path, log_output)

class FileCreatedHandler(FileSystemEventHandler):
    def __init__(self, log_output):
        self.log_output = log_output

    def on_created(self, event):
        if not event.is_directory:
            file_path = event.src_path
            self.log_output.insert(tk.END, f"\n📂 New file detected: {file_path}\n")
            self.log_output.update()
            scan_file(file_path, self.log_output)

def start_watching(folder_path, log_output):
    event_handler = FileCreatedHandler(log_output)
    observer = Observer()
    observer.schedule(event_handler, folder_path, recursive=True)
    observer.start()

    def run_observer():
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

    threading.Thread(target=run_observer, daemon=True).start()

def choose_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        log_output.delete(1.0, tk.END)
        log_output.insert(tk.END, f"📁 Selected folder: {folder_path}\n\n")
        log_output.update()
        iterate_files(folder_path, log_output)
        start_watching(folder_path, log_output)
        log_output.insert(tk.END, f"\n👁️ Watching for new files in: {folder_path}\n")
        log_output.update()

# ---------- GUI Design ----------
root = tk.Tk()
root.title("Antivirus Scanner - VirusTotal")
root.geometry("800x650")
root.configure(bg="#f0f4f8")

title_label = tk.Label(
    root,
    text="Antivirus Scanner",
    font=("Segoe UI", 24, "bold"),
    fg="#2c3e50",
    bg="#f0f4f8"
)
title_label.pack(pady=10)

frame = tk.Frame(root, bg="#f0f4f8")
frame.pack(pady=5)

scan_button = tk.Button(
    frame,
    text="🔎 Select Folder to Scan",
    command=choose_folder,
    font=("Segoe UI", 14),
    bg="#3498db",
    fg="white",
    activebackground="#2980b9",
    padx=20,
    pady=10,
    relief="flat",
    cursor="hand2"
)
scan_button.pack()

log_output = scrolledtext.ScrolledText(
    root,
    width=95,
    height=25,
    font=("Consolas", 10),
    bg="white",
    fg="#2c3e50",
    borderwidth=2,
    relief="groove"
)
log_output.pack(pady=15)

root.mainloop()
