import requests
import base64
import re
import os
import ssl
import socket
import customtkinter as ctk
from PIL import Image
from colorama import Fore, init
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors

init(autoreset=True)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


#  API Key
 
VT_API_KEY = "YOUR_API_KEY_HERE"



class CyberAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Investigator Pro - Mahmoud Ashraf")
        self.geometry("1000x950")

        self.header = ctk.CTkLabel(self, text="Cyber Link Investigator", font=("Roboto", 28, "bold"))
        self.header.pack(pady=15)

        self.url_entry = ctk.CTkEntry(self, placeholder_text="Enter the URL for security clearance...", width=600, height=45)
        self.url_entry.pack(pady=5)

        self.scan_btn = ctk.CTkButton(self, text="RUN SECURITY ANALYSIS", command=self.start_analysis, font=("Roboto", 18, "bold"), height=40)
        self.scan_btn.pack(pady=10)

        self.result_box = ctk.CTkTextbox(self, width=850, height=250, font=("Consolas", 14))
        self.result_box.pack(pady=10)

        self.img_label = ctk.CTkLabel(self, text="[ System Sandbox Preview ]")
        self.img_label.pack(pady=10)

        self.pdf_btn = ctk.CTkButton(self, text="DOWNLOAD PDF REPORT", command=self.save_pdf, state="disabled", fg_color="#2ecc71", text_color="black", font=("Roboto", 16, "bold"), height=40)
        self.pdf_btn.pack(pady=20)

        self.report_data = {}

    def check_ssl(self, url):
        try:
            hostname = url.replace("https://", "").replace("http://", "").split('/')[0]
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])['commonName']
                    return f"Verified (Issued by: {issuer})"
        except:
            return "Unverified (Potential Security Risk)"

    def start_analysis(self):
        url = self.url_entry.get().strip()
        if not url: return
        if not url.startswith("http"): url = "https://" + url

        self.result_box.delete("0.0", "end")
        self.result_box.insert("insert", f"[*] Starting analysis for: {url}\n")
        self.update()

        try:
            risk_score = 0
            if any(word in url.lower() for word in ['login', 'bank', 'verify', 'account']): risk_score += 2
            if any(srv in url.lower() for srv in ['trycloudflare', 'ngrok', 'serveo']): risk_score += 3
            if len(url) > 85: risk_score += 1
            risk_score = min(risk_score, 5)

            res = requests.get(url, timeout=10, allow_redirects=True)
            final_url = res.url
            
            ssl_status = self.check_ssl(final_url)
            url_id = base64.urlsafe_b64encode(final_url.encode()).decode().strip("=")
            vt_res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY})
            
            vt_summary = "No previous history found."
            if vt_res.status_code == 200:
                s = vt_res.json()['data']['attributes']['last_analysis_stats']
                vt_summary = f"Flagged by {s['malicious']} engines." if s['malicious'] > 0 else "Clean record."
            
            self.result_box.insert("insert", f"[V] Connection Established\n[V] Identity: {ssl_status}\n[V] Reputation: {vt_summary}\n[*] Risk Score: {risk_score}/5\n")
            self.update()

            self.take_gui_screenshot(final_url)

            self.report_data = {
                "url": final_url, "ssl": ssl_status, "reputation": vt_summary,
                "risk": f"{risk_score}/5",
                "verdict": "DANGEROUS [X]" if risk_score >= 3 else "SAFE [V]"
            }

            self.result_box.insert("insert", f"\nFINAL VERDICT: {self.report_data['verdict']}")
            self.pdf_btn.configure(state="normal")

        except Exception as e:
            self.result_box.insert("insert", f"\n[X] Error: {str(e)}")

    def take_gui_screenshot(self, url):
        opts = Options()
        opts.add_argument("--headless")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=opts)
        driver.get(url)
        if not os.path.exists("screenshots"): os.makedirs("screenshots")
        path = "screenshots/preview.png"
        driver.save_screenshot(path)
        driver.quit()
        img = Image.open(path)
        ctk_img = ctk.CTkImage(light_image=img, size=(400, 220))
        self.img_label.configure(image=ctk_img, text="")

    def save_pdf(self):
        filename = "Security_Investigation_Report.pdf"
        c = canvas.Canvas(filename, pagesize=A4)
        width, height = A4

        
        c.setFont("Helvetica-Bold", 22)
        c.drawString(50, height - 60, "Security Investigation Report")
        c.setStrokeColor(colors.black)
        c.line(50, height - 70, width - 50, height - 70)

        
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, height - 100, "Detailed Findings:")
        
        c.setFont("Helvetica", 12)
        y_position = height - 130
        
        report_lines = [
            f"Target URL: {self.report_data['url']}",
            f"Final Verdict: {self.report_data['verdict']}",
            f"Risk Score: {self.report_data['risk']}",
            f"Identity (SSL): {self.report_data['ssl']}",
            f"Reputation: {self.report_data['reputation']}"
        ]

        for line in report_lines:
            
            if "DANGEROUS" in line: c.setFillColor(colors.red)
            elif "SAFE" in line: c.setFillColor(colors.green)
            else: c.setFillColor(colors.black)
            
            c.drawString(60, y_position, line)
            y_position -= 25


        y_position -= 30 
        if os.path.exists("screenshots/preview.png"):
            c.setFillColor(colors.black)
            c.setFont("Helvetica-Bold", 14)
            c.drawString(50, y_position, "Visual Evidence (Sandbox Preview):")
            y_position -= 280
            c.drawImage("screenshots/preview.png", 50, y_position, width=500, height=270, preserveAspectRatio=True)


        c.setFont("Helvetica-Oblique", 10)
        c.setFillColor(colors.gray)
        c.drawString(50, 30, "Report generated by Cyber Investigator Pro v4.5 - Mahmoud Ashraf")

        c.save()
        self.result_box.insert("insert", f"\n\n[V] PDF Repaired & Saved: {filename}")

if __name__ == "__main__":
    app = CyberAnalyzerApp()
    app.mainloop()