import requests

with open("domains.txt", encoding="utf-8") as file:
    for line in file:
        print(line.strip())
response = requests.get("https://example.com", timeout=10)
print(response.status_code)
for key, value in response.headers.items():
    print(f"{key}: {value}")


def check_hsts(header):
    if header == None:
        return ("HSTS", "FAIL", "HSTS is not present")
    elif int(header.split()[0].split("=")[1].rstrip(";")) < 31536000:
        return ("HSTS", "WARN", "max-age is one year or less")
    else:
        return ("HSTS", "PASS", "max-age is one year or more")


header, status, reason = check_hsts(response.headers.get("Strict-Transport-Security"))
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


header2, status2, reason2 = check_CSP(response.headers.get("Content-Security-Policy"))
print(header2, status2, reason2)


def check_XFRAME(header):
    if header == "deny" or "sameorigin" or "none":
        return ("XFO", "PASS", "valid header")
    else:
        return ("XFO", "FAIL", "header missing")


header3, status3, reason3 = check_XFRAME(response.headers.get("X-Frame-Options"))
print(header3, status3, reason3)
