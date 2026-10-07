import socket
import ssl
from datetime import datetime, timezone

import requests

with open("domains.txt", encoding="utf-8") as file:
    domains = []
    for line in file:
        if not line.strip():
            continue
        print(line.strip())
        domains.append(line.strip())
for d in domains:
    try:
        response = requests.get(d, timeout=10)
        print(response.status_code)
    except TimeoutError:
        print(f"{domains}: timed out ")
    except Exception as error:
        print(f"error: {type(error).__name__} {error}")
    else:
        for key, value in response.headers.items():
            print(f"{key}: {value}")

        def check_hsts(header):
            if header == None:
                return ("HSTS", "FAIL", "HSTS is not present")
            elif int(header.split()[0].split("=")[1].rstrip(";")) < 31536000:
                return ("HSTS", "WARN", "max-age is one year or less")
            else:
                return ("HSTS", "PASS", "max-age is one year or more")

        header, status, reason = check_hsts(
            response.headers.get("Strict-Transport-Security")
        )
        print(header, status, reason)

        def check_CSP(header):
            if header == None:
                return ("CSP", "FAIL", "CSP is not present")
            elif "unsafe-inline" in header:
                return ("CSP", "WARN", "allows unsafe-inline")
            elif "unsafe-eval" in header:
                return ("CSP", "WARN", "allows unsafe-eval")
            else:
                return ("CSP", "PASS", "unsafe-inline and eval are not allowed")

        header2, status2, reason2 = check_CSP(
            response.headers.get("Content-Security-Policy")
        )
        print(header2, status2, reason2)

        def check_XFRAME(header):
            if header == "deny" or "sameorigin" or "none":
                return ("XFO", "PASS", "valid header")
            else:
                return ("XFO", "FAIL", "header missing")

        header3, status3, reason3 = check_XFRAME(
            response.headers.get("X-Frame-Options")
        )
        print(header3, status3, reason3)

        def cert_days_left(host, port=443):
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
            exp = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
            )
            return (exp - datetime.now(timezone.utc)).days

        def certgrade(days):
            # cert_days_left("github.com")
            if days <= 7:
                return ("TLS Cert", "FAIL", "under 7 days left")
            elif days <= 30:
                return ("TLS Cert", "WARN", "under 30 days left")
            else:
                return ("TLS Cert", "PASS", "")

        days, status4, reason4 = certgrade(cert_days_left("github.com"))
        print("Days until expiration:", cert_days_left("github.com"))
        print(days, status4, reason4)
