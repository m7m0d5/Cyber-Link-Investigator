# Cyber Link Investigator Pro 

A professional Python-based forensic tool designed to analyze suspicious URLs, perform deep security checks, and generate automated PDF reports. This project bridges the gap between secure coding and real-world Security Operations (SecOps).

##  Key Features
- **Global Threat Intel:** Real-time reputation checks via VirusTotal API integration.
- **SSL/TLS Profiling:** Detailed inspection of certificate issuers and security protocols.
- **Heuristic Risk Engine:** Detects phishing patterns and malicious URL structures even with no prior history.
- **Safe Sandbox Preview:** Captures site screenshots within an **Isolated Virtual Environment (VBox)** using Selenium to prevent drive-by malware.
- **Automated Reporting:** Generates a structured PDF containing all gathered digital evidence.

##  Technical Verdicts
The tool provides a clear security verdict based on multiple factors:
- **Risk Score (0/5 to 5/5):** Based on heuristic analysis and global reputation.
- **Visual Evidence:** Safe preview capture for manual inspection.

##  How to Use

1. **Clone the repository:**
```bash
git clone https://github.com/m7m0d5/Cyber-Link-Investigator.git   
```
2. **Install requirements:**
```bash
pip install -r requirements.txt 