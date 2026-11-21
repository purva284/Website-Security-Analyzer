
# Website Security Analyzer

## 1. Project Overview
Website Security Analyzer is a Python-based cybersecurity project developed to analyze the basic security features of websites. It checks HTTPS connections, HTTP status codes, redirects, and security headers to identify possible security weaknesses.

## 2. Aim
To develop a Python-based tool that analyzes website security and generates a security analysis report.

## 3. Objectives
- To analyze the basic security features of websites.
- To check HTTPS and TLS connections.
- To identify security headers.
- To detect missing security headers.
- To check website redirects and HTTP status codes.
- To generate a security analysis report.

## 4. Technologies Used
- **Programming Language:** Python
- **Library:** Requests
- **Platform:** Visual Studio Code
- **Operating System:** Windows

## 5. Project Features
- Accepts a website URL from the user.
- Checks the HTTP status code.
- Analyzes HTTPS connections.
- Checks TLS connection acceptance.
- Detects website redirects.
- Checks important security headers.
- Identifies missing security headers.
- Generates a text-based security report.

## 6. Security Headers Checked
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy

## 7. How to Run the Project

**Step 1:** Install Python on your computer.

**Step 2:** Install the required Requests library.

```bash
pip install requests
```

**Step 3:** Open the project folder in Visual Studio Code.

**Step 4:** Run the following command in the terminal.

```bash
python website_security_analyzer.py
```

**Step 5:** Enter the website URL when prompted.

## 8. Output
The program displays the website security analysis results in the terminal. It also generates a text file named `website_security_report.txt` containing the analysis details.

## 9. Applications
- Basic website security checking.
- Identifying missing security headers.
- Understanding website security configurations.
- Learning basic cybersecurity concepts.

## 10. Disclaimer
This project is developed for educational purposes. It performs basic website security checks and does not replace a professional security audit.

## 11. Developed By
**Purva Bhujbal**

**Project:** Website Security Analyzer
