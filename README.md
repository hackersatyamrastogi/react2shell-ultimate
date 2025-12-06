# React2Shell Ultimate - CVE-2025-66478 Scanner

<p align="center">
  <img src="https://img.shields.io/badge/CVE-2025--66478-red?style=for-the-badge" alt="CVE-2025-66478">
  <img src="https://img.shields.io/badge/CVE-2025--55182-red?style=for-the-badge" alt="CVE-2025-55182">
  <img src="https://img.shields.io/badge/CVSS-10.0%20CRITICAL-darkred?style=for-the-badge" alt="CVSS 10.0">
  <img src="https://img.shields.io/badge/Python-3.7+-blue?style=for-the-badge&logo=python" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License">
</p>

<p align="center">
  <b>The most comprehensive scanner for Next.js RSC Remote Code Execution vulnerability</b>
</p>

```
╔════════════════════════════════════════════════════════════════════════╗
║     ____                 _   ___  ____  _          _ _                 ║
║    |  _ \ ___  __ _  ___| |_|__ \/ ___|| |__   ___| | |                ║
║    | |_) / _ \/ _` |/ __| __| / /\___ \| '_ \ / _ \ | |                ║
║    |  _ <  __/ (_| | (__| |_ / /_ ___) | | | |  __/ | |                ║
║    |_| \_\___|\__,_|\___|\__|____|____/|_| |_|\___|_|_|                ║
║                                                                        ║
║            React2Shell Ultimate CVE-2025-66478 Scanner v1.0.0         ║
║          Next.js RSC Remote Code Execution Vulnerability               ║
╠════════════════════════════════════════════════════════════════════════╣
║  Author: Satyam Rastogi (@hackersatyamrastogi)                         ║
║  https://github.com/hackersatyamrastogi                                ║
╠════════════════════════════════════════════════════════════════════════╣
║  Modes: --safe (side-channel) | --rce (PoC) | --version | --local      ║
║  WAF Bypass: --waf-bypass | --vercel-bypass | --unicode                ║
╚════════════════════════════════════════════════════════════════════════╝
```

## 🚨 Vulnerability Overview

**CVE-2025-66478** (also known as **CVE-2025-55182**) is a **CRITICAL (CVSS 10.0)** Remote Code Execution vulnerability affecting Next.js applications using React Server Components (RSC).

### Affected Versions
| Version Range | Status |
|--------------|--------|
| Next.js 15.0.0 - 15.0.4 | ⚠️ **Vulnerable** |
| Next.js 15.1.0 - 15.1.8 | ⚠️ **Vulnerable** |
| Next.js 15.2.0 - 15.2.5 | ⚠️ **Vulnerable** |
| Next.js 15.3.0 - 15.3.5 | ⚠️ **Vulnerable** |
| Next.js 15.4.0 - 15.4.7 | ⚠️ **Vulnerable** |
| Next.js 15.5.0 - 15.5.6 | ⚠️ **Vulnerable** |
| Next.js 16.0.0 - 16.0.6 | ⚠️ **Vulnerable** |
| Next.js 14.3.0-canary.77+ | ⚠️ **Vulnerable** |
| Next.js 15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7+ | ✅ Patched |
| Next.js 16.0.7+ | ✅ Patched |
| Next.js 13.x, 14.x stable | ✅ Not Affected |

## ✨ Features

This tool combines the best features from multiple CVE-2025-66478 scanners:

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-Mode Detection** | Safe side-channel, RCE PoC, version-only, local scanning |
| 🛡️ **WAF Bypass Techniques** | Junk data padding, Unicode encoding, Vercel-specific bypass |
| 📁 **Local Project Scanning** | Scan package.json, lockfiles for vulnerable dependencies |
| ⚡ **High Performance** | Multi-threaded scanning with configurable concurrency |
| 📊 **Multiple Output Formats** | Console, JSON, file export |
| 🎯 **Accurate Version Detection** | HTTP headers, RSC fingerprinting, patched version awareness |

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/hackersatyamrastogi/react2shell-ultimate.git
cd react2shell-ultimate

# Install dependencies
pip install -r requirements.txt

# Or install manually
pip install requests tqdm
```

## 📖 Usage

### Basic Scanning

```bash
# Version detection only (fastest, no exploitation)
python3 react2shell-ultimate.py -u https://target.com --version

# Safe side-channel detection (no code execution)
python3 react2shell-ultimate.py -u https://target.com --safe

# RCE proof-of-concept (executes harmless calculation: 41*271=11111)
python3 react2shell-ultimate.py -u https://target.com --rce

# Comprehensive scan with all bypass attempts
python3 react2shell-ultimate.py -u https://target.com --comprehensive
```

### Mass Scanning

```bash
# Scan multiple targets from file
python3 react2shell-ultimate.py -l targets.txt -t 20 -o results.json

# Quiet mode - only show vulnerable hosts
python3 react2shell-ultimate.py -l targets.txt -q

# JSON output to stdout
python3 react2shell-ultimate.py -l targets.txt --json
```

### Local Project Scanning

```bash
# Scan current directory
python3 react2shell-ultimate.py --local .

# Scan specific project path
python3 react2shell-ultimate.py --local /path/to/nextjs/projects
```

### WAF Bypass Techniques

```bash
# Junk data bypass (adds 128KB padding to evade content inspection)
python3 react2shell-ultimate.py -u https://target.com --rce --waf-bypass

# Custom junk data size
python3 react2shell-ultimate.py -u https://target.com --rce --waf-bypass --waf-bypass-size 256

# Unicode encoding bypass
python3 react2shell-ultimate.py -u https://target.com --rce --unicode

# Vercel-specific WAF bypass
python3 react2shell-ultimate.py -u https://target.com --rce --vercel-bypass

# Windows target (PowerShell payload)
python3 react2shell-ultimate.py -u https://target.com --rce --windows
```

### Advanced Options

```bash
# With proxy
python3 react2shell-ultimate.py -u https://target.com --rce --proxy http://127.0.0.1:8080

# Custom headers
python3 react2shell-ultimate.py -u https://target.com --rce -H "Authorization: Bearer token"

# Increased timeout
python3 react2shell-ultimate.py -u https://target.com --rce --timeout 30

# Verbose output
python3 react2shell-ultimate.py -u https://target.com --comprehensive -v
```

## 📋 Command-Line Options

| Option | Description |
|--------|-------------|
| `-u, --url` | Single URL to scan |
| `-l, --list` | File containing URLs (one per line) |
| `--local` | Scan local project directory |
| `--safe` | Safe side-channel detection (no RCE) |
| `--rce` | RCE proof-of-concept mode |
| `--version` | Version detection only |
| `--comprehensive` | Full scan with all techniques |
| `--waf-bypass` | Add junk data for WAF bypass |
| `--waf-bypass-size` | Junk data size in KB (default: 128) |
| `--unicode` | Unicode encoding for WAF bypass |
| `--vercel-bypass` | Vercel-specific WAF bypass |
| `--windows` | Use Windows PowerShell payload |
| `-t, --threads` | Concurrent threads (default: 10) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `-k, --insecure` | Disable SSL verification |
| `--proxy` | Proxy URL (http://host:port) |
| `-H, --header` | Custom header (repeatable) |
| `-o, --output` | Output file (JSON) |
| `--all-results` | Save all results, not just vulnerable |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Only show vulnerable hosts |
| `--json` | JSON output to stdout |
| `--no-color` | Disable colored output |

## 🔬 Detection Methods

### 1. Safe Side-Channel Detection (`--safe`)
Triggers a specific error response pattern without executing any code. Identifies vulnerable RSC implementations through error handling behavior.

### 2. RCE Proof-of-Concept (`--rce`)
Executes a harmless mathematical calculation (`echo $((41*271))` = `11111`) to confirm RCE capability. The result appears in the `X-Action-Redirect` header.

### 3. Version Detection (`--version`)
- Checks `X-Powered-By` header for Next.js version
- Analyzes `Vary` header for RSC indicators
- Probes RSC endpoints for `text/x-component` responses
- Scans page source for Next.js fingerprints

### 4. Local Scanning (`--local`)
Scans project directories for:
- `package.json` - Direct dependency declaration
- `package-lock.json` - NPM lockfile
- `yarn.lock` - Yarn lockfile
- `pnpm-lock.yaml` - PNPM lockfile
- `bun.lockb` - Bun lockfile

## 📊 Output Examples

### Console Output
```
[VULNERABLE] https://target.com
    Version: 15.3.1 | Status: 200 | Method: rce_poc
    WAF Bypass: SUCCESS

[NOT VULNERABLE] https://safe-target.com
    Version: 15.5.7 | Status: 200 | Method: http_headers

[WAF BLOCKED] https://protected.com
    Version: 15.2.0 | Status: 403 | Method: rce_poc
    WAF Detected: Exploit blocked
```

### JSON Output
```json
{
  "tool": "React2Shell Ultimate CVE-2025-66478 Scanner",
  "version": "1.0.0",
  "cve_ids": ["CVE-2025-55182", "CVE-2025-66478"],
  "scan_time": "2025-12-06T12:00:00Z",
  "total_results": 1,
  "results": [
    {
      "url": "https://target.com",
      "vulnerable": true,
      "version": "15.3.1",
      "status_code": 200,
      "detection_method": "rce_poc",
      "waf_detected": false,
      "waf_bypassed": false
    }
  ]
}
```

## 🛡️ Remediation

If you find vulnerable applications:

1. **Upgrade immediately** to patched versions:
   - Next.js 15.x → Upgrade to **15.5.7+** (or your minor version's patch)
   - Next.js 16.x → Upgrade to **16.0.7+**

2. **Temporary mitigations**:
   - Use Edge Runtime instead of Node.js runtime
   - Disable Server Actions if not needed
   - Deploy behind a WAF with RSC payload detection

3. **Monitor** for exploitation attempts in logs

## 📚 References

- [Next.js Security Advisory - CVE-2025-66478](https://nextjs.org/blog/CVE-2025-66478)
- [Assetnote Research - React2Shell](https://www.assetnote.io/)
- [NVD - CVE-2025-66478](https://nvd.nist.gov/vuln/detail/CVE-2025-66478)

## ⚠️ Disclaimer

This tool is provided for **authorized security testing and educational purposes only**.

- Only scan systems you have explicit permission to test
- The RCE PoC mode executes code on target systems (harmless calculation)
- Unauthorized access to computer systems is illegal
- The author is not responsible for misuse of this tool

## 👤 Author

**Satyam Rastogi**
- GitHub: [@hackersatyamrastogi](https://github.com/hackersatyamrastogi)
- Twitter: [@satyamhacker](https://twitter.com/satyamhacker)
- Website: [satyamrastogi.com](https://www.satyamrastogi.com)

## 🤝 Credits

This tool consolidates research and code from:
- [Assetnote](https://www.assetnote.io/) - Original React2Shell research
- [Malayke](https://github.com/Malayke) - Version detection logic
- Security research community

## 📄 License

MIT License - See [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>⭐ Star this repo if you find it useful! ⭐</b>
</p>
