# 🔒 SecureCodeScan — Client-Side Vulnerability Checker

![CI](https://img.shields.io/badge/status-active-success?style=flat-square)

A **lightweight, client-side security tool** that scans pasted code for **common vulnerabilities** before it reaches production.  
Perfect for quickly identifying insecure patterns in HTML, JavaScript, and CSS — **all offline**.

**Live Demo:** _(Coming soon)_

---

## 🚀 Features
- **⚡ Real-time scanning** — Detects issues instantly as you paste code.
- **🛡️ Vulnerability checks** for:
  - `eval()` and `innerHTML` injections
  - Insecure HTTP requests
  - Hardcoded credentials
  - Inline event handlers (XSS risk)
- **🔍 Detailed feedback** — Shows *why* something is risky and how to fix it.
- **📦 100% client-side** — No server calls, runs entirely in the browser.
- **🌙 Dark mode** for better accessibility.

---

## 📸 Screenshot
![SecureCodeScan UI](28d90f35-a4cb-4b98-8854-880e727f16c4.png)

---

## 🛠️ Tech Stack
- **HTML5**
- **CSS3** (responsive, accessible UI)
- **Vanilla JavaScript (ES6+)**
- No frameworks — zero dependencies.

---

## 🧩 How It Works
1. Paste your source code into the input box.
2. The app runs a set of **regex-based security checks** in the browser.
3. A list of **detected issues + severity ratings** is displayed.
4. Suggestions are provided for safe alternatives.

---

## 🏃 Quick Start
```bash
# Install dependencies
npm ci

# Run locally
npm run dev
```

Then open: http://127.0.0.1:5173


---

##  Roadmap

 Add AI-powered code review via OpenAI API

 Export scan reports as PDF

 Support scanning entire repos


👨‍💻 Author

Built by Giuseppe — Mathematics BSc Hons | Aspiring Software Engineer & Cybersecurity Enthusiast.
