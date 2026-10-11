## Python Domain Security Scanner

**What does this tool do?**

This tool is a domain security scanner. When given a list of domains, it checks and reports whether each site sends the important HTTP security headers and how long until it's TLS Certificate expires. It then takes the headers from each site that are either not present or fail to meet the determined criteria,as well as the TLS Certificates that fail to me the determined criteria and outputs them into a table with the header's assigned status.

**What is being checked for?**
- HSTS (Strict-Transport-Security):
HSTS is a web security policy that forces browsers to connect with a website using only secure HTTPS connections.
This is important because this prevents man-in-the-middle (MITM) attacks, SSL stripping, protocol downgrade attacks, and cookie hijacking

- CSP (Content-Security-Policy):
CSP is a web security policy that protects websites from Cross-Site Scripting (XSS). It controls where scripts, styles and frames can load from.

- X-Frame Options:


