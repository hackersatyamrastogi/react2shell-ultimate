# React2Shell Ultimate Scanner

**Professional Next.js RSC RCE Vulnerability Scanner for CVE-2025-66478**

## 🎯 Overview

React2Shell Ultimate is a comprehensive vulnerability scanner for CVE-2025-66478 - a critical Remote Code Execution (RCE) vulnerability affecting Next.js applications using React Server Components (RSC).

## ✨ Features

- 🔍 Multiple Scan Modes (Safe, RCE, Version, Comprehensive)
- 🛡️ Advanced WAF Bypass Techniques
- ⚡ God Mode: Interactive Shell & File Reading
- 🎯 Batch Scanning with Threading
- 📊 JSON Output for Automation
- 🔒 Safe Mode for Non-Invasive Detection

## 🚀 Quick Start

```bash
# Basic scan
python3 react2shell-ultimate.py -u https://target.com

# RCE mode
python3 react2shell-ultimate.py -u https://target.com --mode rce

# Execute command (God Mode)
python3 react2shell-ultimate.py -u https://target.com --exec "id"

# Interactive shell
python3 react2shell-ultimate.py -u https://target.com --shell
```

## 📦 Installation

```bash
git clone https://github.com/hackersatyamrastogi/react2shell-ultimate.git
cd react2shell-ultimate
pip3 install requests urllib3 tqdm
chmod +x react2shell-ultimate.py
```

## 🌐 Web Platform

**Live Scanner:** [www.react2shellscanner.com](https://www.react2shellscanner.com)
**API:** [api.react2shellscanner.com](https://api.react2shellscanner.com)

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is designed for:
- Authorized penetration testing
- Bug bounty programs
- Security research
- Educational purposes

**You are fully responsible for any misuse of this tool.**

## 👨‍💻 Author

**Satyam Rastogi**

- 🌐 Website: [satyamrastogi.com](https://www.satyamrastogi.com)
- 💼 GitHub: [@hackersatyamrastogi](https://github.com/hackersatyamrastogi)
- 🐦 Twitter: [@hackersatyamrastogi](https://twitter.com/hackersatyamrastogi)

---

**Made with ❤️ by Satyam Rastogi**
