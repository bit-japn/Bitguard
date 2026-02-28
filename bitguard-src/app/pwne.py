import requests
import hashlib

m = hashlib.sha256()
m.update(b"1234")

cifrada = m.hexdigest()[0:5].upper()

print(cifrada)

url = f"https://api.pwnedpasswords.com/range/{cifrada}"

response = requests.get(url)

print(response.text.splitlines())