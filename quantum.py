"""
Quantum-Inspired Digital Forensics Toolkit
File: Quantum_Forensics_Toolkit.py

Features:
- Modern Tkinter GUI with ttk.Notebook (tabs)
- File Integrity Checker (MD5, SHA1, SHA256)
- Batch File Scanner: search for emails, SSNs, AWS keys, possible secrets in files/folders
- File Metadata viewer
- Secure Key Generator (secrets)
- Password Analyzer + Quantum-inspired brute-force estimator
- Entropy Calculator for files (useful to detect compressed/encrypted content)
- Export scan reports to TXT/CSV
- Background threading for long-running tasks and progress updates

Run: python Quantum_Forensics_Toolkit.py
Dependencies: standard library only (optional matplotlib if you want charts)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os
import re
import time
import threading
import secrets
import string
import math
import csv
from collections import Counter

# ----------------------- Utility functions -----------------------

def compute_hash(file_path, algo='sha256'):
    h = hashlib.new(algo)
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR: {e}"


def file_entropy(path):
    try:
        with open(path, 'rb') as f:
            data = f.read()
        if not data:
            return 0.0
        counts = Counter(data)
        entropy = 0.0
        length = len(data)
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception as e:
        return None


def secure_random_key(length=32):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def quantum_brute_force_estimate(charset_size, length):
    # Classical: charset_size ** length
    # Quantum (Grover-like): sqrt(classical) ~ charset_size ** (length/2)
    classical = charset_size ** length
    quantum = int(classical ** 0.5)
    return classical, quantum


# Patterns for batch scanning (can be extended)
SCAN_PATTERNS = {
    'Emails': re.compile(rb'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'),
    'AWS Access Key': re.compile(rb'AKIA[0-9A-Z]{16}'),
    'Potential Private Key': re.compile(rb'-----BEGIN [A-Z ]+PRIVATE KEY-----'),
    'SSN-like': re.compile(rb'\b\d{3}-\d{2}-\d{4}\b'),
    'CreditCard-like': re.compile(rb'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b')
}

# ----------------------- GUI Application -----------------------

class ForensicsToolkit(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Quantum-Inspired Digital Forensics Toolkit")
        self.geometry("900x600")
        self.minsize(820, 480)

        self._create_widgets()
        self.report_rows = []

    def _create_widgets(self):
        # Top frame with toolbar
        toolbar = ttk.Frame(self)
        toolbar.pack(side='top', fill='x')

        ttk.Button(toolbar, text='Open File...', command=self.open_file_dialog).pack(side='left', padx=4, pady=6)
        ttk.Button(toolbar, text='Open Folder (Scan)', command=self.open_folder_dialog).pack(side='left', padx=4)
        ttk.Button(toolbar, text='Export Report', command=self.export_report).pack(side='left', padx=4)
        ttk.Button(toolbar, text='Clear Report', command=self.clear_report).pack(side='left', padx=4)

        # Notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill='both', expand=True, padx=8, pady=8)

        # Tabs
        self.tab_dashboard = ttk.Frame(self.nb)
        self.tab_file = ttk.Frame(self.nb)
        self.tab_scan = ttk.Frame(self.nb)
        self.tab_password = ttk.Frame(self.nb)
        self.tab_keygen = ttk.Frame(self.nb)
        self.tab_reports = ttk.Frame(self.nb)

        self.nb.add(self.tab_dashboard, text='Dashboard')
        self.nb.add(self.tab_file, text='File Tools')
        self.nb.add(self.tab_scan, text='Batch Scanner')
        self.nb.add(self.tab_password, text='Password Tools')
        self.nb.add(self.tab_keygen, text='Key Generator')
        self.nb.add(self.tab_reports, text='Reports')

        self._build_dashboard()
        self._build_file_tab()
        self._build_scan_tab()
        self._build_password_tab()
        self._build_keygen_tab()
        self._build_reports_tab()

        # Status bar
        self.status_var = tk.StringVar(value='Ready')
        statusbar = ttk.Label(self, textvariable=self.status_var, relief='sunken', anchor='w')
        statusbar.pack(side='bottom', fill='x')

    # ---------------- Dashboard ----------------
    def _build_dashboard(self):
        frame = self.tab_dashboard
        ttk.Label(frame, text='Toolkit Dashboard', font=('Helvetica', 16, 'bold')).pack(pady=8)
        info = (
            "Features:\n"
            "- File hashing & integrity checks\n"
            "- Batch scanning for emails, keys, and secrets\n"
            "- Entropy analysis to spot encrypted/compressed files\n"
            "- Password strength analysis with quantum-inspired estimates\n"
            "- Secure key generation and exportable reports"
        )
        ttk.Label(frame, text=info, justify='left').pack(padx=10, pady=6)

    # ---------------- File tab ----------------
    def _build_file_tab(self):
        frame = self.tab_file
        left = ttk.Frame(frame)
        left.pack(side='left', fill='y', padx=8, pady=8)
        right = ttk.Frame(frame)
        right.pack(side='left', fill='both', expand=True, padx=8, pady=8)

        ttk.Button(left, text='Select File', command=self.open_file_dialog).pack(pady=4)
        ttk.Label(left, text='Hash Algorithm:').pack(pady=4)
        self.hash_algo = tk.StringVar(value='sha256')
        ttk.OptionMenu(left, self.hash_algo, 'sha256', 'md5', 'sha1', 'sha256').pack()
        ttk.Button(left, text='Compute Hash', command=self.compute_file_hash).pack(pady=6)
        ttk.Button(left, text='Compute Entropy', command=self.compute_file_entropy).pack(pady=6)
        ttk.Button(left, text='Show Metadata', command=self.show_file_metadata).pack(pady=6)

        self.file_text = tk.Text(right, wrap='word')
        self.file_text.pack(fill='both', expand=True)

        self.current_file = None

    def open_file_dialog(self):
        path = filedialog.askopenfilename()
        if path:
            self.current_file = path
            self.file_text.delete('1.0', tk.END)
            self.file_text.insert(tk.END, f'Selected: {path}\n')
            self.status_var.set(f'File selected: {os.path.basename(path)}')

    def compute_file_hash(self):
        path = self.current_file
        if not path:
            messagebox.showwarning('No file', 'Please select a file first.')
            return
        algo = self.hash_algo.get()
        self.status_var.set('Computing hash...')
        threading.Thread(target=self._compute_hash_thread, args=(path, algo), daemon=True).start()

    def _compute_hash_thread(self, path, algo):
        h = compute_hash(path, algo)
        text = f'{algo.upper()}({os.path.basename(path)}): {h}\n'
        self.file_text.insert(tk.END, text)
        self.report_rows.append(('hash', path, algo, h))
        self.status_var.set('Hash computed')

    def compute_file_entropy(self):
        path = self.current_file
        if not path:
            messagebox.showwarning('No file', 'Please select a file first.')
            return
        self.status_var.set('Computing entropy...')
        threading.Thread(target=self._entropy_thread, args=(path,), daemon=True).start()

    def _entropy_thread(self, path):
        e = file_entropy(path)
        self.file_text.insert(tk.END, f'Entropy({os.path.basename(path)}): {e}\n')
        self.report_rows.append(('entropy', path, e))
        self.status_var.set('Entropy computed')

    def show_file_metadata(self):
        path = self.current_file
        if not path:
            messagebox.showwarning('No file', 'Please select a file first.')
            return
        try:
            st = os.stat(path)
            info = (
                f'Path: {path}\nSize: {st.st_size} bytes\n'
                f'Created: {time.ctime(st.st_ctime)}\nModified: {time.ctime(st.st_mtime)}\n'
                f'Accessed: {time.ctime(st.st_atime)}\n'
            )
            self.file_text.insert(tk.END, info)
            self.report_rows.append(('metadata', path, st.st_size))
        except Exception as e:
            messagebox.showerror('Error', str(e))

    # ---------------- Batch Scanner ----------------
    def _build_scan_tab(self):
        frame = self.tab_scan
        top = ttk.Frame(frame)
        top.pack(side='top', fill='x', padx=8, pady=6)
        ttk.Label(top, text='Select Folder to scan (recursively):').pack(side='left')
        ttk.Button(top, text='Choose Folder', command=self.select_scan_folder).pack(side='left', padx=6)
        ttk.Button(top, text='Start Scan', command=self.start_scan).pack(side='left', padx=6)
        ttk.Button(top, text='Stop Scan', command=self.stop_scan).pack(side='left', padx=6)

        self.scan_folder_var = tk.StringVar()
        ttk.Label(frame, textvariable=self.scan_folder_var).pack(anchor='w', padx=10)

        # Results pane
        self.scan_results = tk.Text(frame, wrap='none')
        self.scan_results.pack(fill='both', expand=True, padx=8, pady=8)

        self._scan_stop = threading.Event()
        self._scan_thread = None

    def select_scan_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.scan_folder_var.set(folder)

    def start_scan(self):
        folder = self.scan_folder_var.get()
        if not folder:
            messagebox.showwarning('No folder', 'Please select a folder to scan.')
            return
        self.scan_results.delete('1.0', tk.END)
        self._scan_stop.clear()
        self.status_var.set('Scanning...')
        self._scan_thread = threading.Thread(target=self._scan_folder_thread, args=(folder,), daemon=True)
        self._scan_thread.start()

    def stop_scan(self):
        self._scan_stop.set()
        self.status_var.set('Scan stopping...')

    def _scan_folder_thread(self, folder):
        for root, dirs, files in os.walk(folder):
            if self._scan_stop.is_set():
                break
            for fname in files:
                path = os.path.join(root, fname)
                try:
                    with open(path, 'rb') as f:
                        data = f.read()
                except Exception:
                    continue
                for label, pattern in SCAN_PATTERNS.items():
                    if pattern.search(data):
                        line = f'[{label}] {path}\n'
                        self.scan_results.insert(tk.END, line)
                        self.report_rows.append(('scan', label, path))
                # small delay to remain responsive
                if self._scan_stop.is_set():
                    break
        self.status_var.set('Scan finished' if not self._scan_stop.is_set() else 'Scan stopped')

    # ---------------- Password Tools ----------------
    def _build_password_tab(self):
        frame = self.tab_password
        top = ttk.Frame(frame)
        top.pack(side='top', fill='x', pady=8)

        ttk.Label(top, text='Enter Password:').pack(side='left')
        self.pwd_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.pwd_var, show='*', width=30).pack(side='left', padx=6)
        ttk.Button(top, text='Analyze', command=self.analyze_password).pack(side='left')

        self.pwd_text = tk.Text(frame, height=12)
        self.pwd_text.pack(fill='both', expand=True, padx=8, pady=8)

    def analyze_password(self):
        pwd = self.pwd_var.get()
        if not pwd:
            messagebox.showwarning('Input', 'Enter a password')
            return
        length = len(pwd)
        categories = 0
        if re.search(r'[a-z]', pwd): categories += 1
        if re.search(r'[A-Z]', pwd): categories += 1
        if re.search(r'\d', pwd): categories += 1
        if re.search(r'[^A-Za-z0-9]', pwd): categories += 1

        # approximate charset size
        charset = 26
        if re.search(r'[A-Z]', pwd): charset += 26
        if re.search(r'\d', pwd): charset += 10
        if re.search(r'[^A-Za-z0-9]', pwd): charset += 32

        classical, quantum = quantum_brute_force_estimate(charset, length)

        entropy_per_char = math.log2(charset)
        est_entropy = round(entropy_per_char * length, 2)

        score = est_entropy
        if score < 28:
            strength = 'Very Weak'
        elif score < 36:
            strength = 'Weak'
        elif score < 60:
            strength = 'Reasonable'
        elif score < 128:
            strength = 'Strong'
        else:
            strength = 'Very Strong'

        self.pwd_text.delete('1.0', tk.END)
        self.pwd_text.insert(tk.END, f'Length: {length}\n')
        self.pwd_text.insert(tk.END, f'Categories matched: {categories}/4\n')
        self.pwd_text.insert(tk.END, f'Estimated entropy: {est_entropy} bits\n')
        self.pwd_text.insert(tk.END, f'Password strength: {strength}\n\n')
        self.pwd_text.insert(tk.END, f'Classical brute-force attempts: ~{classical}\n')
        self.pwd_text.insert(tk.END, f'Quantum (Grover-like) attempts: ~{quantum}\n')

        self.report_rows.append(('password_analysis', pwd, est_entropy, strength))

    # ---------------- Key Generator ----------------
    def _build_keygen_tab(self):
        frame = self.tab_keygen
        ttk.Label(frame, text='Secure Key Generator', font=('Helvetica', 12)).pack(pady=6)
        controls = ttk.Frame(frame)
        controls.pack(pady=4)
        ttk.Label(controls, text='Length:').pack(side='left')
        self.key_length_var = tk.IntVar(value=32)
        ttk.Entry(controls, textvariable=self.key_length_var, width=6).pack(side='left', padx=4)
        ttk.Button(controls, text='Generate', command=self.generate_key).pack(side='left', padx=6)

        self.key_text = tk.Text(frame, height=6)
        self.key_text.pack(fill='both', expand=True, padx=8, pady=8)

    def generate_key(self):
        length = self.key_length_var.get()
        if length <= 0 or length > 4096:
            messagebox.showwarning('Input', 'Enter a length between 1 and 4096')
            return
        key = secure_random_key(length)
        self.key_text.delete('1.0', tk.END)
        self.key_text.insert(tk.END, key)
        self.report_rows.append(('keygen', len(key), key[:8] + '...'))

    # ---------------- Reports ----------------
    def _build_reports_tab(self):
        frame = self.tab_reports
        ttk.Label(frame, text='Report Viewer', font=('Helvetica', 12)).pack(pady=6)
        self.report_tree = ttk.Treeview(frame, columns=('type', 'info', 'extra'))
        self.report_tree.heading('#0', text='Index')
        self.report_tree.heading('type', text='Type')
        self.report_tree.heading('info', text='Info')
        self.report_tree.heading('extra', text='Extra')
        self.report_tree.column('#0', width=60)
        self.report_tree.pack(fill='both', expand=True, padx=8, pady=8)

    def clear_report(self):
        self.report_rows.clear()
        for i in self.report_tree.get_children():
            self.report_tree.delete(i)
        self.status_var.set('Report cleared')

    def export_report(self):
        if not self.report_rows:
            messagebox.showinfo('No data', 'No report data to export')
            return
        f = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv'), ('Text', '*.txt')])
        if not f:
            return
        try:
            if f.lower().endswith('.csv'):
                with open(f, 'w', newline='', encoding='utf-8') as csvf:
                    writer = csv.writer(csvf)
                    writer.writerow(['Type', 'Field1', 'Field2', 'Field3'])
                    for row in self.report_rows:
                        writer.writerow(row)
            else:
                with open(f, 'w', encoding='utf-8') as tf:
                    for row in self.report_rows:
                        tf.write(str(row) + '\n')
            messagebox.showinfo('Saved', f'Report saved to {f}')
            self.status_var.set(f'Report exported: {os.path.basename(f)}')
        except Exception as e:
            messagebox.showerror('Error', str(e))

    # ---------------- Folder scan entry point ----------------
    def open_folder_dialog(self):
        folder = filedialog.askdirectory()
        if folder:
            self.scan_folder_var.set(folder)
            self.nb.select(self.tab_scan)


# -------------------- Run application --------------------

if __name__ == '__main__':
    app = ForensicsToolkit()
    app.mainloop()
