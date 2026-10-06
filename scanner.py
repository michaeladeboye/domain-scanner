import ssl, socket, requests
with open("domains.txt", encoding="utf-8") as file:
    for line in file:
        print(line.strip())
response = requests.get("https://github.com", timeout=5)
print(response.status_code)
for key,value in response.headers.items():
    print(f"{key}: {value} ")
def checkheaders(domain,reason):
    if 
        return {"domain": domain, "FAIL": reason}
r=checkheaders("github.com")
print(r)
