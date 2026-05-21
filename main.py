# Arnob Mandal
# Digital Forensics Toolkit
# Simple student-level Python project

import os
import hashlib
import csv
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

SIGNATURES = {
    b"\xff\xd8\xff": ("jpg", b"\xff\xd9"),
    b"\x89PNG\r\n\x1a\n": ("png", b"IEND\xaeB`\x82"),
    b"%PDF": ("pdf", b"%%EOF"),
    b"PK\x03\x04": ("zip_docx", None)
}

class ForensiKitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ForensiKit - Digital Forensics Toolkit")
        self.root.geometry("900x650")

        title = tk.Label(root, text="ForensiKit", font=("Arial", 24, "bold"))
        title.pack(pady=10)

        subtitle = tk.Label(root, text="Simple Digital Forensics Toolkit")
        subtitle.pack()

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="Recover Files", width=20, command=self.recover_files).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="Generate Hash", width=20, command=self.generate_hash).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(btn_frame, text="Extract Metadata", width=20, command=self.extract_metadata).grid(row=0, column=2, padx=5, pady=5)
        tk.Button(btn_frame, text="Scan Suspicious Files", width=20, command=self.scan_suspicious).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(btn_frame, text="Analyze Log File", width=20, command=self.analyze_log).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(btn_frame, text="Create Report", width=20, command=self.create_report).grid(row=1, column=2, padx=5, pady=5)
        tk.Button(btn_frame, text="Clear Output", width=20, command=self.clear_output).grid(row=2, column=1, padx=5, pady=5)

        self.output = scrolledtext.ScrolledText(root, width=105, height=28)
        self.output.pack(pady=10)

        self.log("ForensiKit started.")
        self.log("Choose a tool above to begin.\n")

    def log(self, text):
        self.output.insert(tk.END, text + "\n")
        self.output.see(tk.END)

    def clear_output(self):
        self.output.delete("1.0", tk.END)

    def recover_files(self):
        file_path = filedialog.askopenfilename(title="Choose raw image or binary file")
        if not file_path:
            return

        recovered_dir = "recovered_files"
        os.makedirs(recovered_dir, exist_ok=True)

        with open(file_path, "rb") as f:
            data = f.read()

        count = 0
        self.log("Scanning for file signatures...")

        for sig, info in SIGNATURES.items():
            ext, end_sig = info
            start = 0

            while True:
                start = data.find(sig, start)
                if start == -1:
                    break

                if end_sig is not None:
                    end = data.find(end_sig, start)
                    if end == -1:
                        start += len(sig)
                        continue
                    end += len(end_sig)
                else:
                    end = min(start + 500000, len(data))

                file_data = data[start:end]
                out_name = f"recovered_{count}.{ext}"
                out_path = os.path.join(recovered_dir, out_name)

                with open(out_path, "wb") as out:
                    out.write(file_data)

                self.log(f"Recovered: {out_path}")
                count += 1
                start = end

        self.log(f"Recovery finished. Files recovered: {count}\n")

    def generate_hash(self):
        file_path = filedialog.askopenfilename(title="Choose file to hash")
        if not file_path:
            return

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        self.log("Hash Results:")
        self.log(f"File: {file_path}")
        self.log(f"MD5: {md5.hexdigest()}")
        self.log(f"SHA1: {sha1.hexdigest()}")
        self.log(f"SHA256: {sha256.hexdigest()}\n")

    def extract_metadata(self):
        file_path = filedialog.askopenfilename(title="Choose file for metadata")
        if not file_path:
            return

        stat = os.stat(file_path)
        self.log("Metadata:")
        self.log(f"File: {file_path}")
        self.log(f"Size: {stat.st_size} bytes")
        self.log(f"Created: {datetime.fromtimestamp(stat.st_ctime)}")
        self.log(f"Modified: {datetime.fromtimestamp(stat.st_mtime)}")
        self.log(f"Accessed: {datetime.fromtimestamp(stat.st_atime)}\n")

    def scan_suspicious(self):
        folder = filedialog.askdirectory(title="Choose folder to scan")
        if not folder:
            return

        suspicious = []
        risky_exts = [".exe", ".bat", ".cmd", ".scr", ".js", ".vbs"]

        self.log("Scanning folder for suspicious files...")

        for root, dirs, files in os.walk(folder):
            for name in files:
                path = os.path.join(root, name)
                lower = name.lower()

                reason = []
                if any(lower.endswith(ext) for ext in risky_exts):
                    reason.append("risky extension")
                if lower.count(".") >= 2:
                    reason.append("double extension")
                if name.startswith("."):
                    reason.append("hidden file")
                try:
                    if os.path.getsize(path) == 0:
                        reason.append("empty file")
                except OSError:
                    pass

                if reason:
                    suspicious.append((path, ", ".join(reason)))
                    self.log(f"Flagged: {path} | {', '.join(reason)}")

        self.log(f"Scan complete. Suspicious files found: {len(suspicious)}\n")

    def analyze_log(self):
        file_path = filedialog.askopenfilename(title="Choose log file")
        if not file_path:
            return

        keywords = ["failed", "failure", "denied", "unauthorized", "error", "attack", "malware", "brute", "invalid"]
        hits = []

        with open(file_path, "r", errors="ignore") as f:
            for num, line in enumerate(f, start=1):
                lower = line.lower()
                for word in keywords:
                    if word in lower:
                        hits.append((num, word, line.strip()))
                        break

        self.log("Log Analysis Results:")
        for hit in hits[:100]:
            self.log(f"Line {hit[0]} | Keyword: {hit[1]} | {hit[2]}")

        self.log(f"Total suspicious log lines found: {len(hits)}\n")

    def create_report(self):
        os.makedirs("reports", exist_ok=True)
        report_name = "reports/forensic_report.txt"
        content = self.output.get("1.0", tk.END)

        with open(report_name, "w") as f:
            f.write("ForensiKit Digital Forensics Report\n")
            f.write("Generated: " + str(datetime.now()) + "\n")
            f.write("=" * 50 + "\n\n")
            f.write(content)

        self.log(f"Report saved to {report_name}\n")
        messagebox.showinfo("Report Created", f"Report saved to {report_name}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ForensiKitApp(root)
    root.mainloop()
