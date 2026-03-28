import tkinter as tk
from tkinter import ttk, messagebox
import requests
import json
import threading

class AttackSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("virex - Attack Simulator")
        self.root.geometry("600x500")
        self.root.configure(bg="#0f172a")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Color Palette
        self.bg_dark = "#0f172a"
        self.primary = "#00d2ff"
        self.danger = "#ef4444"
        self.text_light = "#f8fafc"

        self.setup_ui()
        self.update_status()

    def setup_ui(self):
        # Header
        header = tk.Label(self.root, text="🛡️ ATTACK SIMULATOR", font=("Inter", 18, "bold"), 
                        bg=self.bg_dark, fg=self.primary, pady=20)
        header.pack()

        # Target Frame
        target_frame = tk.LabelFrame(self.root, text=" Configuration ", bg=self.bg_dark, fg=self.primary, 
                                  font=("Inter", 10, "bold"), padx=10, pady=10)
        target_frame.pack(fill="x", padx=20, pady=10)

        tk.Label(target_frame, text="Target API URL:", bg=self.bg_dark, fg=self.text_light).grid(row=0, column=0, sticky="w")
        self.url_entry = tk.Entry(target_frame, width=40, bg="#1e293b", fg=self.text_light, insertbackground="white")
        self.url_entry.insert(0, "http://localhost:5000")
        self.url_entry.grid(row=0, column=1, padx=10, pady=5)

        # Attack Selection
        tk.Label(target_frame, text="Attack Type:", bg=self.bg_dark, fg=self.text_light).grid(row=1, column=0, sticky="w")
        self.attack_type = ttk.Combobox(target_frame, values=["SQL Injection", "XSS", "Brute Force", "Scanner", "ML Anomaly"])
        self.attack_type.set("SQL Injection")
        self.attack_type.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        self.attack_type.bind("<<ComboboxSelected>>", self.on_type_change)

        # Payload Selection
        payload_frame = tk.LabelFrame(self.root, text=" Payload & Data ", bg=self.bg_dark, fg=self.primary, 
                                    font=("Inter", 10, "bold"), padx=10, pady=10)
        payload_frame.pack(fill="both", expand=True, padx=20, pady=10)

        tk.Label(payload_frame, text="Endpoint:", bg=self.bg_dark, fg=self.text_light).grid(row=0, column=0, sticky="w")
        self.endpoint_entry = tk.Entry(payload_frame, width=40, bg="#1e293b", fg=self.text_light)
        self.endpoint_entry.insert(0, "/api/users")
        self.endpoint_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(payload_frame, text="Payload:", bg=self.bg_dark, fg=self.text_light).grid(row=1, column=0, sticky="nw")
        self.payload_text = tk.Text(payload_frame, height=5, width=40, bg="#1e293b", fg=self.text_light)
        self.payload_text.insert("1.0", "1' OR '1'='1")
        self.payload_text.grid(row=1, column=1, padx=10, pady=5)

        # Status Bar
        self.status_label = tk.Label(self.root, text="Status: Checking Target...", bg=self.bg_dark, fg="gray")
        self.status_label.pack(pady=5)

        # Action Button
        self.fire_btn = tk.Button(self.root, text="🚀 FIRE ATTACK", command=self.fire_attack, 
                                bg=self.primary, fg="black", font=("Inter", 12, "bold"), 
                                padx=20, pady=10, relief="flat")
        self.fire_btn.pack(pady=20)

    def on_type_change(self, event):
        etype = self.attack_type.get()
        self.payload_text.delete("1.0", tk.END)
        self.endpoint_entry.delete(0, tk.END)
        
        if etype == "SQL Injection":
            self.endpoint_entry.insert(0, "/api/users")
            self.payload_text.insert("1.0", "1' OR '1'='1")
        elif etype == "XSS":
            self.endpoint_entry.insert(0, "/api/data")
            self.payload_text.insert("1.0", "<script>alert('Target Found')</script>")
        elif etype == "Brute Force":
            self.endpoint_entry.insert(0, "/api/login")
            self.payload_text.insert("1.0", '{"username": "admin", "password": "password123"}')
        elif etype == "Scanner":
            self.endpoint_entry.insert(0, "/admin.php")
            self.payload_text.insert("1.0", "GET Request Probe")
        elif etype == "ML Anomaly":
            self.endpoint_entry.insert(0, "/api/data")
            self.payload_text.insert("1.0", "abnormally large data sequence " * 10)

    def update_status(self):
        def check():
            try:
                url = self.url_entry.get() + "/api/health"
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    self.status_label.config(text="Status: API Online ✅", fg="#10b981")
                else:
                    self.status_label.config(text=f"Status: API Error {r.status_code} ⚠️", fg="#f59e0b")
            except:
                self.status_label.config(text="Status: API Offline ❌", fg=self.danger)
            self.root.after(5000, self.update_status)
        
        threading.Thread(target=check, daemon=True).start()

    def fire_attack(self):
        payload = self.payload_text.get("1.0", tk.END).strip()
        url = self.url_entry.get() + self.endpoint_entry.get()
        
        self.fire_btn.config(state="disabled", text="SENDING...")
        
        def send():
            try:
                # Determine request type based on endpoint or simple logic
                if "login" in url or "data" in url:
                    try:
                        data = json.loads(payload)
                        r = requests.post(url, json=data, timeout=3)
                    except json.JSONDecodeError:
                        r = requests.post(url, data=payload, timeout=3)
                else:
                    r = requests.get(url, params={"id": payload}, timeout=3)
                
                msg = f"Response Code: {r.status_code}\nContent: {r.text[:100]}..."
                messagebox.showinfo("Attack Result", msg)
            except Exception as e:
                messagebox.showerror("Attack Failed", str(e))
            finally:
                self.fire_btn.config(state="normal", text="🚀 FIRE ATTACK")

        threading.Thread(target=send, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = AttackSimulatorGUI(root)
    root.mainloop()
