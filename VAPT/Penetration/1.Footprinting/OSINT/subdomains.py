import requests

r = requests.get('https://crt.sh/?q=booking.com&output=json')
data = list(r.json())
subdomains = set()
for i in data:
    subdomains.add(str(i['common_name']))

subdomains = list(subdomains)    

subdomains2 = []

for i in subdomains:
    if i.endswith('booking.com'):
        subdomains2.append(i)

for i in range(0,len(subdomains2)):
    print(i," ", subdomains2[i])


