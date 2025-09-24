#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PomoSec – Pomodoro Edition
Author: Karim Hekal © 2025
"""
import json
import os
import uuid
import webbrowser
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, Toplevel, StringVar, messagebox, IntVar
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from plyer import notification

APP_NAME = "PomoSec"
THEME = "superhero"
DATA_FILE = "data.json"
DEFAULT_POMODORO = 25

CATEGORIES = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
    "Other": "Other Bugs",
    "API": "API Vulnerabilities"
}

VULNS = {
    "A01": [
        "Vertical Privilege Escalation", "Horizontal Privilege Escalation",
        "IDOR (Insecure Direct Object References)", "Path Traversal", "Directory Traversal",
        "Forced Browsing", "Missing Function Level Access Control", "File Upload Vulnerabilities",
        "Unrestricted File Upload", "File Extension Bypass", "MIME Type Bypass",
        "Double Extension Attack", "Null Byte Injection", "Magic Bytes Bypass",
        "ZIP Slip Attack", "Path Traversal via Upload", "File Overwrite", "Web Shell Upload"
    ],
    "A02": [
        "Weak Encryption Algorithms", "Hard-coded Credentials", "Weak Random Number Generation",
        "SSL/TLS Misconfigurations", "Hash Collisions", "Padding Oracle Attacks",
        "Clear Text Storage", "MD5/SHA1 Usage"
    ],
    "A03": [
        "SQL Injection", "NoSQL Injection", "LDAP Injection", "XPath Injection",
        "Command Injection", "Code Injection", "Email Header Injection", "CRLF Injection",
        "XSS (Cross-Site Scripting)", "Reflected XSS", "Stored XSS", "DOM-based XSS",
        "XXE (XML External Entity)", "LFI (Local File Inclusion)", "RFI (Remote File Inclusion)",
        "RCE (Remote Code Execution)", "Deserialization Attacks", "SSTI (Server-Side Template Injection)",
        "CSTI (Client-Side Template Injection)"
    ],
    "A04": [
        "Missing Security Controls", "Insecure Architecture", "Threat Modeling Failures",
        "Business Logic Flaws", "Insufficient Risk Analysis", "Security by Obscurity",
        "Unlimited Resource Consumption"
    ],
    "A05": [
        "Default Credentials", "Directory Listing", "Unnecessary Services",
        "Missing Security Headers", "Verbose Error Messages", "Outdated Software",
        "Missing Security Patches", "Open Cloud Storage"
    ],
    "A06": [
        "Known Vulnerable Libraries", "Outdated Frameworks", "Unpatched Dependencies",
        "EOL (End of Life) Software", "Third-party Component Risks", "Supply Chain Attacks"
    ],
    "A07": [
        "Brute Force Attacks", "Credential Stuffing", "Session Fixation", "Session Hijacking",
        "Weak Password Policies", "Missing Multi-Factor Authentication", "Predictable Session IDs",
        "Password Reset Flaws"
    ],
    "A08": [
        "Unsigned Code", "Insecure Deserialization", "Tampering Attacks",
        "Auto-Update Vulnerabilities", "CI/CD Pipeline Attacks", "Package Repository Poisoning",
        "Code Signing Issues"
    ],
    "A09": [
        "Insufficient Logging", "Log Injection", "Missing Alert Systems", "Log Tampering",
        "Inadequate Incident Response", "Poor Log Management", "Missing Audit Trails"
    ],
    "A10": [
        "Internal Network Scanning", "Cloud Metadata Access", "Port Scanning",
        "Protocol Smuggling", "Blind SSRF", "DNS Rebinding", "HTTP Parameter Pollution"
    ],
    "Other": [
        "CORS Misconfiguration", "Subdomain Takeover", "HTTP Host Header Injection",
        "HTTP Request Smuggling", "HTTP Response Splitting", "Race Conditions",
        "TOCTOU (Time of Check Time of Use)", "Payment Race Conditions", "Account Creation Race",
        "Coupon/Voucher Race", "Time-based Attacks", "Blind Vulnerabilities",
        "Business Logic Vulnerabilities", "WebSocket Vulnerabilities", "DOM Clobbering",
        "Prototype Pollution", "Client-side Prototype Pollution", "Server-side Prototype Pollution",
        "JSON.parse Prototype Pollution", "Object.assign Prototype Pollution", "Open Redirect"
    ],
    "API": [
        "API Key Exposure", "Rate Limiting Bypass", "GraphQL Injection",
        "REST API Vulnerabilities", "API Versioning Issues", "JWT None Algorithm",
        "JWT Key Confusion", "JWT Secret Brute Force", "OAuth Vulnerabilities",
        "API Documentation Exposure"
    ]
}

# ------------------- DATA -------------------
def ensure_keys(vuln):
    vuln.setdefault("pomodoro_sessions", 0)
    vuln.setdefault("pomodoro_duration", DEFAULT_POMODORO)
    return vuln

def load_data():
    if not os.path.exists(DATA_FILE):
        data = {"vulnerabilities": []}
        for code, name in CATEGORIES.items():
            for v in VULNS[code]:
                data["vulnerabilities"].append({
                    "id": str(uuid.uuid4()),
                    "cat_code": code,
                    "cat_name": name,
                    "name": v,
                    "status": "pending",
                    "time_spent": 0,
                    "pomodoro_duration": DEFAULT_POMODORO,
                    "notes": "",
                    "completed_at": None,
                    "sources": []
                })
        save_data(data)
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
    for v in data["vulnerabilities"]:
        ensure_keys(v)
    return data

def save_data(data):
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

# ------------------- Edit Window -------------------
class EditWindow(Toplevel):
    def __init__(self, parent, data, vuln=None, on_save=None, on_pomodoro_change=None):
        super().__init__(parent)
        self.data = data
        self.vuln = vuln
        self.on_save = on_save
        self.on_pomodoro_change = on_pomodoro_change
        self.title("إضافة / تعديل ثغرة")
        self.geometry("650x730")
        self.transient(parent)
        self.grab_set()
        self.resizable(False, False)
        self.build_ui()

    def build_ui(self):
        tb.Label(self, text="اسم الثغرة:").pack(anchor=W, padx=10, pady=5)
        self.name_var = StringVar(value=self.vuln["name"] if self.vuln else "")
        tb.Entry(self, textvariable=self.name_var).pack(fill=X, padx=10)

        tb.Label(self, text="الفئة:").pack(anchor=W, padx=10, pady=5)
        self.cat_var = StringVar(value=self.vuln["cat_code"] if self.vuln else "A01")
        tb.OptionMenu(self, self.cat_var, self.cat_var.get(), *CATEGORIES.keys()).pack(fill=X, padx=10)

        tb.Label(self, text="الحالة:").pack(anchor=W, padx=10, pady=5)
        self.status_var = StringVar(value=self.vuln["status"] if self.vuln else "pending")
        tb.OptionMenu(self, self.status_var, self.status_var.get(), "pending", "in-progress", "completed").pack(fill=X, padx=10)

        tb.Label(self, text="مدة جلسة البومودورو (بالدقائق):").pack(anchor=W, padx=10, pady=5)
        self.pomodoro_var = IntVar(value=self.vuln["pomodoro_duration"] if self.vuln else DEFAULT_POMODORO)
        tb.Spinbox(self, from_=5, to=60, textvariable=self.pomodoro_var, width=10).pack(fill=X, padx=10)

        tb.Label(self, text="ملاحظات:").pack(anchor=W, padx=10, pady=5)
        self.notes_text = tb.Text(self, height=8)
        self.notes_text.pack(fill=BOTH, expand=True, padx=10)
        if self.vuln:
            self.notes_text.insert(1.0, self.vuln["notes"])

        tb.Label(self, text="مصادر (رابط لكل سطر):").pack(anchor=W, padx=10, pady=5)
        self.sources_text = tb.Text(self, height=6)
        self.sources_text.pack(fill=BOTH, expand=True, padx=10)
        if self.vuln and self.vuln["sources"]:
            self.sources_text.insert(1.0, "\n".join(self.vuln["sources"]))

        btn_frm = tb.Frame(self)
        btn_frm.pack(fill=X, pady=10)
        tb.Button(btn_frm, text="💾 حفظ", command=self.save).pack(side=RIGHT, padx=5)
        tb.Button(btn_frm, text="إلغاء", style="Outline.TButton", command=self.destroy).pack(side=RIGHT)

    def save(self):
        new_name = self.name_var.get().strip()
        if not new_name:
            return
        old_duration = self.vuln["pomodoro_duration"] if self.vuln else DEFAULT_POMODORO
        new_duration = self.pomodoro_var.get()

        if self.vuln:
            self.vuln["name"] = new_name
            self.vuln["cat_code"] = self.cat_var.get()
            self.vuln["cat_name"] = CATEGORIES[self.cat_var.get()]
            self.vuln["status"] = self.status_var.get()
            self.vuln["pomodoro_duration"] = new_duration
            self.vuln["notes"] = self.notes_text.get(1.0, END).strip()
            self.vuln["sources"] = [s.strip() for s in self.sources_text.get(1.0, END).splitlines() if s.strip()]
            if self.vuln["status"] == "completed" and not self.vuln["completed_at"]:
                self.vuln["completed_at"] = datetime.now().isoformat()
        else:
            self.data["vulnerabilities"].append({
                "id": str(uuid.uuid4()),
                "cat_code": self.cat_var.get(),
                "cat_name": CATEGORIES[self.cat_var.get()],
                "name": new_name,
                "status": self.status_var.get(),
                "time_spent": 0,
                "pomodoro_duration": new_duration,
                "notes": self.notes_text.get(1.0, END).strip(),
                "completed_at": None,
                "sources": [s.strip() for s in self.sources_text.get(1.0, END).splitlines() if s.strip()]
            })

        if new_duration != old_duration and self.on_pomodoro_change:
            self.on_pomodoro_change(new_duration)

        save_data(self.data)
        if self.on_save:
            self.on_save()
        self.destroy()

# ------------------- Main App -------------------
class MainApp(tb.Window):
    def __init__(self):
        super().__init__(themename=THEME, title=APP_NAME, size=(1200, 700))
        self.data = load_data()
        self.current_vuln = None
        self.pomodoro_seconds = None
        self.pomodoro_running = False
        self.after_id = None
        self.pomodoro_start_time = None
        self.eval('tk::PlaceWindow . center')
        self.build_ui()
        self.apply_styles()
        self.fill_tree()

    def apply_styles(self):
        self.style.configure("Treeview", rowheight=40, font=("Segoe UI", 12))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 13, "bold"))
        self.style.configure("TButton", font=("Segoe UI", 11))
        self.style.configure("dark.TFrame", background="#1a1d21")
        self.style.configure("header.TFrame", background="#1a1d21")

    def build_ui(self):
        hdr = tb.Frame(self, padding=8, style="header.TFrame")
        hdr.pack(side=TOP, fill=X)
        tb.Label(hdr, text="🔒 PomoSec - Pomodoro Edition", font=("Segoe UI", 16, "bold"),
                 foreground="#e9ecef", background=self.style.lookup("header.TFrame", "background")).pack(anchor="center")

        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL, bd=0, sashwidth=4, bg=self.style.lookup('TFrame', 'background'))
        paned.pack(fill=BOTH, expand=True)

        sidebar_frame = tb.Frame(paned)
        paned.add(sidebar_frame, stretch="always")
        self.build_sidebar(sidebar_frame)

        content_frame = tb.Frame(paned)
        paned.add(content_frame, stretch="always")
        self.content = content_frame
        self.build_content_area()

        self.build_footer()

    def build_footer(self):
        footer = tb.Frame(self, padding=6, style="dark.TFrame")
        footer.pack(side=BOTTOM, fill=X, pady=0)
        sig = "© 2025 Karim Hekal  –  PomoSec "
        lbl = tb.Label(
            footer,
            text=sig,
            font=("Segoe UI", 11, "bold"),
            foreground="#e9ecef",
            background="#1a1d21"
        )
        lbl.pack(anchor="center", pady=4)

    def build_sidebar(self, parent):
        tb.Label(parent, text="📊 الفئات", font=("Segoe UI", 14, "bold")).pack(anchor=W, pady=5)
        self.tree = ttk.Treeview(parent, show="tree", selectmode="browse")
        self.tree.pack(fill=BOTH, expand=True)
        self.tree.column("#0", width=300)
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        tb.Button(parent, text="+ إضافة ثغرة جديدة", command=self.add_vuln).pack(fill=X, pady=5)

    def fill_tree(self):
        icons = {"pending": "⚪", "in-progress": "🔵", "completed": "✅"}
        for code, name in CATEGORIES.items():
            vulns = [v for v in self.data["vulnerabilities"] if v["cat_code"] == code]
            done = len([v for v in vulns if v["status"] == "completed"])
            progress = int((done / len(vulns)) * 100) if vulns else 0
            parent = self.tree.insert("", "end", text=f"{code}: {name}  ({progress}%)", tags=(code,))
            for v in vulns:
                self.tree.insert(parent, "end", text=f"{icons.get(v['status'], '⚪')} {v['name']}", tags=(v["id"],))

    def on_tree_select(self, _):
        sel = self.tree.selection()
        if not sel:
            return
        item = self.tree.item(sel[0])
        tags = item["tags"]
        for t in tags:
            if t in [v["id"] for v in self.data["vulnerabilities"]]:
                self.current_vuln = t
                self.build_content_area()
                break

    def build_content_area(self):
        for w in self.content.winfo_children():
            w.destroy()
        if not self.current_vuln:
            tb.Label(self.content, text="اختر ثغرة من القائمة لبدء التعلم", font=("Segoe UI", 20)).pack(expand=True)
            return

        v = next((v for v in self.data["vulnerabilities"] if v["id"] == self.current_vuln), None)
        if not v:
            return

        title_bar = tb.Frame(self.content)
        title_bar.pack(fill=X, pady=8)
        tb.Label(title_bar, text=v["name"], font=("Segoe UI", 20, "bold")).pack(side=LEFT, padx=6)
        timer_frm = tb.Frame(title_bar)
        timer_frm.pack(side=RIGHT, padx=6)
        self.timer_lbl = tb.Label(timer_frm, text=f"{v['pomodoro_duration']:02d}:00", font=("Segoe UI", 18, "bold"))
        self.timer_lbl.pack(side=TOP)
        btn_frm = tb.Frame(timer_frm)
        btn_frm.pack(side=TOP, pady=4)
        tb.Button(btn_frm, text="▶", width=4, command=self.start_pomodoro).pack(side=LEFT, padx=2)
        tb.Button(btn_frm, text="⏸", width=4, command=self.pause_pomodoro).pack(side=LEFT, padx=2)
        tb.Button(btn_frm, text="⏹", width=4, command=self.reset_pomodoro).pack(side=LEFT, padx=2)

        frm = tb.Frame(self.content)
        frm.pack(fill=X, pady=6)
        icons = {"pending": "⚪", "in-progress": "🔵", "completed": "✅"}
        self.status_lbl = tb.Label(frm, text=f"{icons[v['status']]} {v['status'].replace('-', ' ').title()}",
                                   font=("Segoe UI", 12, "bold"))
        self.status_lbl.pack(side=LEFT, padx=5)
        if v["status"] != "completed":
            complete_btn = tb.Button(frm, text="Complete", style="success.TButton",
                                     command=lambda: self.mark_completed(v))
            complete_btn.pack(side=LEFT, padx=5)
        tb.Button(frm, text="✏ تعديل", command=lambda: self.edit_vuln(v["id"])).pack(side=LEFT, padx=5)
        tb.Button(frm, text="🗑 حذف", command=lambda: self.delete_vuln(v["id"])).pack(side=LEFT)

        sessions_frm = tb.Frame(self.content)
        sessions_frm.pack(fill=X, pady=6)
        self.sessions_lbl = tb.Label(sessions_frm, text=f"عدد الجلسات المكتملة: {v['pomodoro_sessions']}", font=("Segoe UI", 12))
        self.sessions_lbl.pack(side=LEFT)
        self.time_lbl = tb.Label(sessions_frm, text=f"الوقت المستغرق: {v['time_spent']} دقيقة", font=("Segoe UI", 12))
        self.time_lbl.pack(side=LEFT, padx=20)

        tb.Label(self.content, text="📝 ملاحظاتك:", font=("Segoe UI", 12)).pack(anchor=W, pady=(8, 2))
        self.notes_text = tb.Text(self.content, height=6)
        self.notes_text.pack(fill=X)
        self.notes_text.insert(1.0, v["notes"])
        tb.Button(self.content, text="💾 احفظ الملاحظات", command=self.save_notes).pack(pady=5)

        if v["sources"]:
            tb.Label(self.content, text="📚 مصادر:", font=("Segoe UI", 12, "bold")).pack(anchor=W, pady=(10, 2))
            for src in v["sources"]:
                link = tb.Label(self.content, text=src, foreground="dodgerblue", cursor="hand2")
                link.pack(anchor=W)
                link.bind("<Button-1>", lambda e, u=src: webbrowser.open_new(u) if u.startswith("http") else None)

        cat = [c for c in self.data["vulnerabilities"] if c["cat_code"] == v["cat_code"]]
        done = len([c for c in cat if c["status"] == "completed"])
        progress = int((done / len(cat)) * 100) if cat else 0
        self.cat_progress_lbl = tb.Label(self.content, text=f"تقدم الفئة: {progress}% ({done}/{len(cat)})", font=("Segoe UI", 12))
        self.cat_progress_lbl.pack(pady=5)
        self.cat_pb = tb.Progressbar(self.content, value=progress, style=SUCCESS)
        self.cat_pb.pack(fill=X, padx=20, pady=5)

    def save_notes(self):
        v = next((v for v in self.data["vulnerabilities"] if v["id"] == self.current_vuln), None)
        if v:
            v["notes"] = self.notes_text.get(1.0, END).strip()
            save_data(self.data)

    def delete_vuln(self, vuln_id):
        v = next((v for v in self.data["vulnerabilities"] if v["id"] == vuln_id), None)
        if v and messagebox.askyesno("تأكيد", f"حذف الثغرة '{v['name']}'؟"):
            self.data["vulnerabilities"] = [x for x in self.data["vulnerabilities"] if x["id"] != vuln_id]
            save_data(self.data)
            self.tree.delete(*self.tree.get_children())
            self.fill_tree()
            self.current_vuln = None
            self.build_content_area()

    def add_vuln(self):
        EditWindow(self, self.data, on_save=lambda: self.refresh_after_edit(), on_pomodoro_change=self.update_pomodoro_display)

    def edit_vuln(self, vid):
        vuln = next((v for v in self.data["vulnerabilities"] if v["id"] == vid), None)
        EditWindow(self, self.data, vuln=vuln, on_save=lambda: self.refresh_after_edit(), on_pomodoro_change=self.update_pomodoro_display)

    def refresh_after_edit(self):
        save_data(self.data)
        self.tree.delete(*self.tree.get_children())
        self.fill_tree()
        self.build_content_area()

    def update_pomodoro_display(self, new_duration):
        self.pomodoro_seconds = new_duration * 60
        if not self.pomodoro_running:
            self.timer_lbl.config(text=f"{new_duration:02d}:00")
        v = next((v for v in self.data["vulnerabilities"] if v["id"] == self.current_vuln), None)
        if v:
            self.update_icon_and_progress(v)

    def update_icon_and_progress(self, vuln):
        icons = {"pending": "⚪", "in-progress": "🔵", "completed": "✅"}
        for item in self.tree.get_children():
            for child in self.tree.get_children(item):
                if vuln["id"] in self.tree.item(child)["tags"]:
                    self.tree.item(child, text=f"{icons.get(vuln['status'], '⚪')} {vuln['name']}")
                    self.update_cat_progress(vuln["cat_code"])
                    return

    def update_cat_progress(self, cat_code):
        vulns = [v for v in self.data["vulnerabilities"] if v["cat_code"] == cat_code]
        done = len([v for v in vulns if v["status"] == "completed"])
        progress = int((done / len(vulns)) * 100) if vulns else 0
        if hasattr(self, 'cat_progress_lbl') and self.cat_progress_lbl.winfo_exists():
            self.cat_progress_lbl.config(text=f"تقدم الفئة: {progress}% ({done}/{len(vulns)})")
        if hasattr(self, 'cat_pb') and self.cat_pb.winfo_exists():
            self.cat_pb.config(value=progress)
        for item in self.tree.get_children():
            if cat_code in self.tree.item(item)["tags"]:
                name = CATEGORIES[cat_code]
                self.tree.item(item, text=f"{cat_code}: {name}  ({progress}%)")
                break

    def update_status_label(self, vuln):
        icons = {"pending": "⚪", "in-progress": "🔵", "completed": "✅"}
        if hasattr(self, 'status_lbl') and self.status_lbl.winfo_exists():
            self.status_lbl.config(text=f"{icons[vuln['status']]} {vuln['status'].replace('-', ' ').title()}")

    def mark_completed(self, vuln):
        vuln["status"] = "completed"
        if not vuln["completed_at"]:
            vuln["completed_at"] = datetime.now().isoformat()
        if self.pomodoro_running and self.pomodoro_start_time:
            elapsed_seconds = (datetime.now() - self.pomodoro_start_time).total_seconds()
            vuln["time_spent"] += int(elapsed_seconds // 60)
            vuln["pomodoro_sessions"] += 1
            if hasattr(self, 'sessions_lbl') and self.sessions_lbl.winfo_exists():
                self.sessions_lbl.config(text=f"عدد الجلسات المكتملة: {vuln['pomodoro_sessions']}")
            if hasattr(self, 'time_lbl') and self.time_lbl.winfo_exists():
                self.time_lbl.config(text=f"الوقت المستغرق: {vuln['time_spent']} دقيقة")
            notification.notify(title="✅ تم الإكمال", message=f"أُضيفت {int(elapsed_seconds//60)} دقيقة للوقت المستغرق.", app_name=APP_NAME, timeout=3)
        self.pause_pomodoro()
        self.reset_pomodoro()
        save_data(self.data)
        self.update_icon_and_progress(vuln)
        self.update_status_label(vuln)
        self.build_content_area()

    def start_pomodoro(self):
        if not self.pomodoro_running:
            v = next((v for v in self.data["vulnerabilities"] if v["id"] == self.current_vuln), None)
            if not v:
                messagebox.showwarning("لم تختر مهمة", "اختر ثغرة أولاً لبدء الجلسة.")
                return
            if v["status"] != "in-progress":
                v["status"] = "in-progress"
                self.update_status_label(v)
                self.update_icon_and_progress(v)
                save_data(self.data)
            self.pomodoro_seconds = v["pomodoro_duration"] * 60
            self.pomodoro_start_time = datetime.now()
            self.pomodoro_running = True
            self.tick()

    def pause_pomodoro(self):
        self.pomodoro_running = False
        if self.after_id:
            self.after_cancel(self.after_id)

    def reset_pomodoro(self):
        self.pause_pomodoro()
        v = next((v for v in self.data["vulnerabilities"] if v["id"] == self.current_vuln), None)
        if v and hasattr(self, 'timer_lbl') and self.timer_lbl.winfo_exists():
            self.timer_lbl.config(text=f"{v['pomodoro_duration']:02d}:00")

    def tick(self):
        if self.pomodoro_running and self.pomodoro_seconds > 0:
            self.pomodoro_seconds -= 1
            mins, secs = divmod(self.pomodoro_seconds, 60)
            if hasattr(self, 'timer_lbl') and self.timer_lbl.winfo_exists():
                self.timer_lbl.config(text=f"{mins:02d}:{secs:02d}")
            v = next((v for v in self.data["vulnerabilities"] if v["id"] == self.current_vuln), None)
            if v and self.pomodoro_start_time and hasattr(self, 'time_lbl') and self.time_lbl.winfo_exists():
                elapsed_seconds = (datetime.now() - self.pomodoro_start_time).total_seconds()
                current_minutes = int(elapsed_seconds // 60)
                self.time_lbl.config(text=f"الوقت المستغرق: {current_minutes} دقيقة")
            self.after_id = self.after(1000, self.tick)
        elif self.pomodoro_running and self.pomodoro_seconds == 0:
            self.pomodoro_running = False
            notification.notify(title="⏰ Pomodoro", message="انتهت الجلسة! خذ استراحة.", app_name=APP_NAME, timeout=4)

# ------------------- RUN -------------------
if __name__ == "__main__":
    MainApp().mainloop()