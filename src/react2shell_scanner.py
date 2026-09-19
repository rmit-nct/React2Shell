#!/usr/bin/env python3
import argparse
import json
import re
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

# Disable SSL Certificate warnings
requests.packages.urllib3.disable_warnings()

BOUNDARY = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
GRAY = "\033[90m"
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RULE = "─" * 72
CVE_ID = "CVE-2025-55182"

VULNERABILITY_RULES = {
    "react",
    "react-dom",
    "react-server-dom-webpack",
    "react-server-dom-parcel",
    "react-server-dom-turbopack",
    "next",
}

ASCII_LOGO = r"""
               #####////
            ###########///
          NN###########////
         NNNN###########///
        NNNNN###########///
      NNNNNNN###########///   NNNNNN#///
     NNNNNNNN###########///NNNNNNNNNNN#///
    NNNNNNNNNN###########/NNNNNNNNNNNN///
   NNNNNNNNNNN###########NNNNNNNNNNN#//
 NNNNNNNNNNNN/###########NNNNNNNNNN///
NNNNNNNNNNN#//###########NNNNNNNNN///
  NNNNNNNN///  ###########NNNNNN#///
     NNNN///   ###########NNNNN///
               ###########NNNN///
               ###########NN#///
                ###########///
                  ########///
                      ###///
"""


def colorize_logo(art):
    """Color the three planes sampled from transparent.webp."""
    return (
        art.replace("N", f"{BLUE}N{RESET}")
        .replace("#", f"{CYAN}#{RESET}")
        .replace("/", f"{YELLOW}/{RESET}")
    )


NCT_BANNER = (
    f"{BOLD}{colorize_logo(ASCII_LOGO)}"
    f"{MAGENTA}          R E A C T 2 S H E L L{RESET}\n"
    f"{GRAY}           RSC vulnerability scanner{RESET}\n"
)


def print_banner():
    """Print the ASCII rendering of the NCT logo."""
    print(NCT_BANNER)
    print(f"{GRAY}{RULE}{RESET}")
    print()


def format_detail(message):
    """Wrap verbose response details to the report width."""
    lines = textwrap.wrap(str(message), width=58) or [""]
    formatted = [f"   {GRAY}└─ Detail{RESET}  {lines[0]}"]
    formatted.extend(f"              {line}" for line in lines[1:])
    return "\n".join(formatted)


def build_safe_payload():
    """Builds a safe side-channel payload (no RCE execution)."""
    body = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="1"\r\n\r\n'
        "{}\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="0"\r\n\r\n'
        '["$1:aa:aa"]\r\n'
        f"--{BOUNDARY}--"
    )
    return body


def check_target(url, timeout=10):
    """Send the non-executing side-channel probe and evaluate the response."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    url = url.rstrip("/")

    headers = {
        "User-Agent": "RSC-Scanner-Light/1.0",
        "Next-Action": "x",
        "X-Nextjs-Request-Id": "b5dce965",
        "Content-Type": f"multipart/form-data; boundary={BOUNDARY}",
        "X-Nextjs-Html-Request-Id": "SSTMXm7OJ_g0Ncx6jpQt9",
    }

    body = build_safe_payload()

    try:
        res = requests.post(
            url,
            headers=headers,
            data=body.encode("utf-8"),
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )

        server_header = res.headers.get("Server", "Unknown")
        powered_by = res.headers.get("X-Powered-By", "")
        next_page = res.headers.get("X-Nextjs-Page", "")

        tech_stack = []
        if "next" in powered_by.lower() or next_page:
            tech_stack.append("Next.js")
        if "vercel" in server_header.lower():
            tech_stack.append("Vercel WAF/Edge")
        elif "netlify" in server_header.lower() or "Netlify-Vary" in res.headers:
            tech_stack.append("Netlify")
        elif "cloudflare" in server_header.lower():
            tech_stack.append("Cloudflare")

        stack_info = ", ".join(tech_stack) if tech_stack else f"Server: {server_header}"

        is_vuln = False
        reason = ""

        if res.status_code == 500 and 'E{"digest"' in res.text:
            if "Vercel" in stack_info or "Netlify" in stack_info:
                reason = "Triggers RSC error pattern but shielded by edge WAF/sanitizer"
            else:
                is_vuln = True
                reason = "Unpatched RSC deserialization (500 internal error with digest leak)"
        elif res.status_code == 404:
            reason = "Endpoint does not expose or accept Next-Action handlers (404 Not Found)"
        else:
            reason = f"Response status {res.status_code} did not match RSC vulnerability signatures"

        return {
            "url": url,
            "status": res.status_code,
            "vulnerable": is_vuln,
            "reason": reason,
            "stack": stack_info,
            "error": None,
        }

    except Exception as e:
        return {
            "url": url,
            "status": None,
            "vulnerable": False,
            "reason": "Connection failed",
            "stack": "N/A",
            "error": str(e),
        }


def parse_semver(version_str):
    """Parse a package version into major, minor, patch, and prerelease."""
    if not isinstance(version_str, str):
        return None
    cleaned = version_str.strip().lstrip("^~>=<v ")
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", cleaned)
    if not match:
        return None
    major, minor, patch, prerelease = match.groups()
    return int(major), int(minor), int(patch), prerelease or ""


def check_version_status(package, version):
    """Evaluate an RSC-related package version against the local rules."""
    parsed = parse_semver(version)
    if not parsed:
        return {
            "status": "UNKNOWN",
            "severity": "LOW",
            "recommendation": f"Unable to resolve version '{version}'; review manually.",
        }

    major, minor, patch, prerelease = parsed
    react_packages = VULNERABILITY_RULES - {"next"}

    if package in react_packages and (major, minor, patch) == (19, 0, 0):
        return {
            "status": "VULNERABLE",
            "severity": "CRITICAL",
            "recommendation": f"Upgrade {package} to >= 19.0.1.",
        }

    if package == "next":
        if major == 13 or (major == 14 and (minor, patch) < (2, 15)):
            return {
                "status": "VULNERABLE",
                "severity": "CRITICAL",
                "recommendation": "Upgrade next to >= 14.2.15.",
            }
        if (major, minor, patch) == (15, 0, 0) and prerelease:
            return {
                "status": "VULNERABLE",
                "severity": "CRITICAL",
                "recommendation": "Upgrade next to >= 15.0.1.",
            }

    return {
        "status": "PATCHED",
        "severity": "NONE",
        "recommendation": "No affected version detected for this package.",
    }


def load_json(path):
    """Load a UTF-8 JSON document."""
    with path.open("r", encoding="utf-8") as file_handle:
        return json.load(file_handle)


def scan_project(project_dir):
    """Inspect package manifests and lock data without executing project code."""
    package_file = project_dir / "package.json"
    lock_file = project_dir / "package-lock.json"
    if not package_file.is_file():
        raise FileNotFoundError("package.json not found in target directory")

    package_data = load_json(package_file)
    lock_data = load_json(lock_file) if lock_file.is_file() else {}

    declared = {}
    for section in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        values = package_data.get(section, {})
        if isinstance(values, dict):
            declared.update(values)

    locked = {}
    for package_path, details in lock_data.get("packages", {}).items():
        if not package_path or not isinstance(details, dict):
            continue
        name = details.get("name") or package_path.rsplit("node_modules/", 1)[-1]
        if name in VULNERABILITY_RULES and details.get("version"):
            locked[name] = details["version"]

    # npm lockfileVersion 1 stores packages under dependencies instead.
    for name, details in lock_data.get("dependencies", {}).items():
        if name in VULNERABILITY_RULES and isinstance(details, dict):
            if details.get("version"):
                locked.setdefault(name, details["version"])

    findings = []
    detected = VULNERABILITY_RULES.intersection(declared.keys() | locked.keys())
    for package in sorted(detected):
        version = locked.get(package, declared.get(package))
        source = "package-lock.json" if package in locked else "package.json"
        result = check_version_status(package, version)
        findings.append(
            {
                "package": package,
                "version": version,
                "source": source,
                "status": result["status"],
                "severity": result["severity"],
                "cve": CVE_ID,
                "recommendation": result["recommendation"],
            }
        )
    return findings


def print_whitebox_results(findings, project_dir):
    """Render local dependency findings using the shared CLI theme."""
    vulnerable = sum(item["status"] == "VULNERABLE" for item in findings)
    unknown = sum(item["status"] == "UNKNOWN" for item in findings)

    print(f"{BOLD}{CYAN}WHITE-BOX CONFIGURATION{RESET}")
    print(f"  {GRAY}Project{RESET}       {project_dir.resolve()}")
    print(f"  {GRAY}Advisory{RESET}      {CVE_ID}")
    print(f"  {GRAY}Method{RESET}        Static dependency inspection (no code execution)")
    print(f"\n{GRAY}{RULE}{RESET}\n{BOLD} RESULTS{RESET}\n{GRAY}{RULE}{RESET}\n")

    if not findings:
        print(f" {GREEN}●{RESET} No targeted React or Next.js packages were detected.\n")

    for item in findings:
        if item["status"] == "VULNERABLE":
            color, marker = RED, "● VULNERABLE"
        elif item["status"] == "UNKNOWN":
            color, marker = YELLOW, "● REVIEW"
        else:
            color, marker = GREEN, "● PATCHED"
        print(f" {color}{BOLD}{marker:<14}{RESET} {BOLD}{item['package']}@{item['version']}{RESET}")
        print(f"   {GRAY}├─ Source{RESET}   {item['source']}")
        print(f"   {GRAY}├─ Severity{RESET} {color}{item['severity']}{RESET}")
        print(f"{format_detail(item['recommendation'])}\n")

    print(f"{GRAY}{RULE}{RESET}\n{BOLD} SCAN COMPLETE{RESET}\n{GRAY}{RULE}{RESET}")
    print(
        f"  {BOLD}{len(findings)}{RESET} detected"
        f"   {GRAY}│{RESET}   {RED}{BOLD}{vulnerable}{RESET} vulnerable"
        f"   {GRAY}│{RESET}   {GREEN}{len(findings) - vulnerable - unknown}{RESET} patched"
        f"   {GRAY}│{RESET}   {YELLOW}{unknown}{RESET} review"
    )
    print(f"{GRAY}{RULE}{RESET}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="Assess React Server Components endpoints for React2Shell.",
        epilog="Use only on systems you own or are explicitly authorized to test.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-l", "--list", help="Path to file containing list of targets")
    parser.add_argument(
        "-w",
        "--whitebox",
        metavar="PATH",
        help="Statically inspect a local Node.js project directory",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="Number of threads (default: 10)"
    )
    parser.add_argument("-o", "--output", help="Output JSON file for results")

    args = parser.parse_args()

    selected_modes = sum(bool(value) for value in (args.url, args.list, args.whitebox))
    if selected_modes != 1:
        parser.error("choose exactly one scan mode: --url, --list, or --whitebox")

    if args.whitebox:
        project_path = Path(args.whitebox).expanduser()
        if not project_path.is_dir():
            parser.error(f"white-box target is not a directory: {project_path}")
        try:
            findings = scan_project(project_path)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            print(f"{RED}[ERROR]{RESET} White-box scan failed: {error}", file=sys.stderr)
            return 2

        print_whitebox_results(findings, project_path)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as file_handle:
                json.dump(findings, file_handle, indent=2)
            print(f"\n{GREEN}[+]{RESET} Findings saved to {BOLD}{args.output}{RESET}")
        return 1 if any(item["status"] == "VULNERABLE" for item in findings) else 0

    targets = []
    if args.url:
        targets.append(args.url)
    elif args.list:
        with open(args.list, "r") as f:
            targets = [
                line.strip() for line in f if line.strip() and not line.startswith("#")
            ]
    mode = "safe side-channel (non-executing)"
    print(f"{BOLD}{CYAN}SCAN CONFIGURATION{RESET}")
    print(f"  {GRAY}Targets{RESET}       {BOLD}{len(targets)}{RESET}")
    print(f"  {GRAY}Threads{RESET}       {BOLD}{args.threads}{RESET}")
    print(f"  {GRAY}Mode{RESET}          {BOLD}{mode}{RESET}")
    print(f"  {GRAY}Output{RESET}        {args.output or 'terminal only'}")
    print(f"\n{GRAY}{RULE}{RESET}")
    print(f"{BOLD} RESULTS{RESET}")
    print(f"{GRAY}{RULE}{RESET}\n")

    results = []
    vuln_count = 0
    safe_count = 0
    error_count = 0

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_target, target): target
            for target in targets
        }
        for future in as_completed(futures):
            res = future.result()
            results.append(res)

            if res["vulnerable"]:
                vuln_count += 1
                print(
                    f" {RED}{BOLD}● VULNERABLE{RESET}  {BOLD}{res['url']}{RESET}\n"
                    f"   {GRAY}├─ HTTP{RESET}    {YELLOW}{res['status']}{RESET}\n"
                    f"   {GRAY}├─ Stack{RESET}   {CYAN}{res['stack']}{RESET}\n"
                    f"{format_detail(res['reason'])}\n"
                )
            elif res["error"]:
                error_count += 1
                print(
                    f" {YELLOW}{BOLD}● ERROR{RESET}       {BOLD}{res['url']}{RESET}\n"
                    f"{MAGENTA}{format_detail(res['error'])}{RESET}\n"
                )
            else:
                safe_count += 1
                print(
                    f" {GREEN}{BOLD}● NOT VULNERABLE{RESET}  {BOLD}{res['url']}{RESET}\n"
                    f"   {GRAY}├─ HTTP{RESET}    {BLUE}{res['status']}{RESET}\n"
                    f"   {GRAY}├─ Stack{RESET}   {CYAN}{res['stack']}{RESET}\n"
                    f"{format_detail(res['reason'])}\n"
                )

    print(f"{GRAY}{RULE}{RESET}")
    print(f"{BOLD} SCAN COMPLETE{RESET}")
    print(f"{GRAY}{RULE}{RESET}")
    print(
        f"  {BOLD}{len(targets)}{RESET} scanned"
        f"   {GRAY}│{RESET}   {RED}{BOLD}{vuln_count}{RESET} vulnerable"
        f"   {GRAY}│{RESET}   {GREEN}{safe_count}{RESET} not vulnerable"
        f"   {GRAY}│{RESET}   {YELLOW}{error_count}{RESET} errors"
    )
    print(f"{GRAY}{RULE}{RESET}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\n{GREEN}[+]{RESET} Scan results saved to {BOLD}{args.output}{RESET}")

    return 1 if vuln_count else 0


if __name__ == "__main__":
    sys.exit(main())
