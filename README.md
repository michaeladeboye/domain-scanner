## Python Domain Security Scanner

## What does this tool do?

This tool is a domain security scanner. When given a list of domains, it checks and reports whether each site sends the important HTTP security headers and how long until it's TLS Certificate expires. It then takes the headers from each site that are either not present or fail to meet the determined criteria,as well as the TLS Certificates that fail to me the determined criteria and outputs them into a table with the header's assigned status.

## What is being checked for?
**HSTS (Strict-Transport-Security):**
- HSTS is a web security policy that forces browsers to connect with a website using only secure HTTPS connections.
- This is important because this prevents man-in-the-middle (MITM) attacks, SSL stripping, protocol downgrade attacks, and cookie hijacking.
- The scanner checks whether or not the `max-age` setting is  greater than or equal to 1 year.

**CSP (Content-Security-Policy):**
- CSP is a web security policy that protects websites from Cross-Site Scripting (XSS). It controls where scripts, styles and frames can load from.
- The scanner checks whether or not CSP is present and whether or not it contains `unsafe-inline` or `unsafe-eval`.

**X-Frame Options:**
- X-Frame Options determines whether a browser can embed a webpage inside an iframe. It stops clickjacking, where another site embeds yours in a hidden iframe.
- The scanner checks X-Frame Options contains `DENY` or `SAMEORIGIN`

**TLS Certificate:**
- A TLS Certificate is a document that verifies the identity of a website and enables encrypted communication through the HTTPS protocol.
- The scanner checks how long until expiry the certificate has.

## Installation

Requires Python 3 (tested on 3.14).

```
git clone https://github.com/michaeladeboye/domain-scanner.git
cd domain-scanner
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Create a text file with one domain per line (no `https://`):

```
github.com
example.com
```

Run a scan:

```
python scanner.py domains.txt
```

Export results:

```
python scanner.py domains.txt --json results.json --csv results.csv
```

Exit code is `0` if nothing FAILs or ERRORs and `1` otherwise, so the scanner
can be used in scheduled jobs or CI pipelines.

## Example Output



