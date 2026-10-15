import argparse
import csv
import json
import socket
import ssl
import sys
from datetime import datetime, timezone

import requests


def check_hsts(header):
    if header is None:
        return ("HSTS", "FAIL", "HSTS is not present")
    elif header is not None:
        parts = header.split(";")
        parts = [part.strip() for part in parts]
        for part in parts:
            if part.upper().startswith("MAX-AGE"):
                x = int(part.split("=")[1])
                if x < 31536000:
                    return ("HSTS", "WARN", "max-age is less than one year")
                else:
                    return ("HSTS", "PASS", "max-age is one year or more")
        return ("HSTS", "FAIL", "max-age is not present")


def check_CSP(header):
    if header is None:
        return ("CSP", "FAIL", "CSP is not present")
    elif "unsafe-inline" in header:
        return ("CSP", "WARN", "allows unsafe-inline")
    elif "unsafe-eval" in header:
        return ("CSP", "WARN", "allows unsafe-eval")
    else:
        return ("CSP", "PASS", "unsafe-inline and eval are not allowed")


def check_XFRAME(header):
    if header is None:
        return ("XFO", "FAIL", "header missing")
    elif header.upper() in ("DENY", "SAMEORIGIN"):
        return ("XFO", "PASS", "valid header")
    else:
        return ("XFO", "FAIL", "wrong header")


def cert_days_left(host, port=443):
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    exp = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
    )
    return (exp - datetime.now(timezone.utc)).days


def certgrade(tls):
    if tls <= 7:
        return ("TLS Cert", "FAIL", "under 7 days left")
    elif tls <= 30:
        return ("TLS Cert", "WARN", "under 30 days left")
    else:
        return ("TLS Cert", "PASS", f"{tls} days left")


def table(rlist):
    print(f"{'DOMAIN':<25} {'HSTS':<6}   {'CSP':<6}  {'XFO':<6}  {'CERT':<6}")
    print("-" * 60)
    for b in rlist:
        print(
            f"{b['domain']:<25} {b['hsts'][1]:<6}   {b['csp'][1]:<6}  {b['xfo'][1]:<6}  {b['cert'][1]:<6}"
        )


def main():
    parser = argparse.ArgumentParser(
        description="Scan domains for security headers and TLS certificate expiry."
    )
    parser.add_argument("file", help="File of domains to scan")
    parser.add_argument("--json", help="Exports results to json")
    parser.add_argument("--csv", help="Exports results to csv")
    args = parser.parse_args()

    with open(args.file, encoding="utf-8") as file:
        domains = []
        for line in file:
            if not line.strip():
                continue
            domains.append(line.strip())

    results = []
    for d in domains:
        hsts = ("HSTS", "ERROR", "could not fetch page")
        csp = ("CSP", "ERROR", "could not fetch page")
        xfo = ("XFO", "ERROR", "could not fetch page")
        ccert = ("TLS Cert", "ERROR", "not_checked")
        try:
            response = requests.get(f"https://{d}", timeout=15)
        except requests.exceptions.Timeout:
            hsts = ("HSTS", "ERROR", "timed out")
            csp = ("CSP", "ERROR", "timed out")
            xfo = ("XFO", "ERROR", "timed out")
            print(f"{d}: timed out ")
        except Exception as error:
            hsts = ("HSTS", "ERROR", str(type(error).__name__))
            csp = ("CSP", "ERROR", str(type(error).__name__))
            xfo = ("XFO", "ERROR", str(type(error).__name__))
        else:
            hsts = check_hsts(response.headers.get("Strict-Transport-Security"))

            csp = check_CSP(response.headers.get("Content-Security-Policy"))

            xfo = check_XFRAME(response.headers.get("X-Frame-Options"))

        try:
            cdl = cert_days_left(d)
        except ssl.SSLCertVerificationError as error:
            ccert = ("TLS Cert", "FAIL", str(error.verify_message))
        except ssl.SSLError as error:
            ccert = ("TLS Cert", "FAIL", str(error.reason))
        except Exception as error:
            ccert = ("TLS Cert", "ERROR", str(type(error).__name__))
        else:
            ccert = certgrade(cdl)

        results.append(
            {
                "domain": d,
                "hsts": (hsts),
                "csp": (csp),
                "xfo": (xfo),
                "cert": (ccert),
            }
        )

    table(results)
    found_problem = False
    print("\n\nIssues:")
    for r in results:
        warnings = [r["hsts"], r["csp"], r["xfo"], r["cert"]]
        for w in warnings:
            if "PASS" not in w[1]:
                print(f"{r['domain']}  {w[0]}  {w[1]}  {w[2]}")
            if (w[1]) in ("FAIL", "ERROR"):
                found_problem = True

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["domain", "check", "status", "reason"])
            for dicts in results:
                findings = [dicts["hsts"], dicts["csp"], dicts["xfo"], dicts["cert"]]
                for finding in findings:
                    writer.writerow(
                        [
                            dicts["domain"],
                            finding[0],
                            finding[1],
                            finding[2],
                        ]
                    )
    if found_problem:
        sys.exit(1)


if __name__ == "__main__":
    main()
