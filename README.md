## Python Domain Security Scanner

**What does this tool do?**
This tool is a domain security scanner. When given a list of domains, it reports whether each site sends the important HTTP security headers and how long until it's TLS Certificate expires. It then takes the headers from each site that are either not present or fail to meet the determined criteria, and outputs them into a table with the header's assigned status. The same thing is done with the TLS Certificate.
