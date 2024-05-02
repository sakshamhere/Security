
# Domain Information

https://www.booking.com/

┌──(kali㉿kali)-[~]
└─$ `nslookup booking.com `           
Server:         192.168.29.1
Address:        192.168.29.1#53

Non-authoritative answer:
Name:   booking.com
Address: 18.172.64.72
Name:   booking.com
Address: 18.172.64.69
Name:   booking.com
Address: 18.172.64.78
Name:   booking.com
Address: 18.172.64.96
       
┌──(kali㉿kali)-[~]
└─$ `ping 18.172.64.72`           
PING 18.172.64.72 (18.172.64.72) 56(84) bytes of data.
64 bytes from 18.172.64.72: icmp_seq=1 ttl=242 time=23.9 ms
64 bytes from 18.172.64.72: icmp_seq=2 ttl=242 time=18.0 ms
^C
--- 18.172.64.72 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 18.011/20.979/23.948/2.968 ms

About:

The Domain allows Travel booking and services

# Online Presence

# 1. Checking SSL Certificate for subdomains

Not much info found

# 2. Checking crt.sh

Got total 678 subdomains from crt.sh, saved them in a file `subdomains.txt`

┌──(kali㉿kali)-[~]
└─$ `curl -s https://crt.sh/\?q\=booking.com\&output\=json | python -m json.tool | grep common_name | cut -d":" -f2 | cut -d'"' -f2 | sort -u >> subdomains.txt`



# 3. List Company Hosted Servers

Filetered domains with `booking.com` which are actually companty hosted servers and get IP of them by using `host` command

┌──(kali㉿kali)-[~]
└─ `cat subdomains.txt | grep booking.com >> company_hosted_domains.txt`

┌──(kali㉿kali)-[~]
└─ `for i in $(cat company_hosted_domains.txt); do host $i | grep "has address" | cut -d" " -f1,4 >> ip_addresses_by_domains.txt; done`

Now we have Ip addresses of servers hosted by company, lets use shodan to get more details like open ports and other


# 4. DNS Records

We got 
- `A` Record which we already know apart from that 
- `NS` Record which are nameservers used to resolve FQDN to IP address
- `MX` Records which are mail servers
- `TXT` Records which gives more info

The Core information we can see right now is

- ZOOM
- Atlassian
- adobe
- cisco
- onetrust

┌──(kali㉿kali)-[~]
└─$ `dig @8.8.8.8 any booking.com`

; <<>> DiG 9.19.19-1-Debian <<>> @8.8.8.8 any booking.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 28179
;; flags: qr rd ra; QUERY: 1, ANSWER: 50, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;booking.com.                   IN      ANY

;; ANSWER SECTION:
booking.com.            60      IN      A       18.172.64.72
booking.com.            60      IN      A       18.172.64.96
booking.com.            60      IN      A       18.172.64.69
booking.com.            60      IN      A       18.172.64.78
booking.com.            300     IN      NS      ns-1288.awsdns-33.org.
booking.com.            300     IN      NS      ns-1959.awsdns-52.co.uk.
booking.com.            300     IN      NS      ns-508.awsdns-63.com.
booking.com.            300     IN      NS      ns-716.awsdns-25.net.
booking.com.            900     IN      SOA     ns-1288.awsdns-33.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400
booking.com.            900     IN      MX      10 mxa-0032a201.gslb.pphosted.com.
booking.com.            900     IN      MX      10 mxb-0032a201.gslb.pphosted.com.
booking.com.            900     IN      TXT     "Dynatrace-site-verification=3a88fc1a-195c-455d-ab87-88d09191496b__drhtlct978bncn9utek6qdqapk"
booking.com.            900     IN      TXT     "MS=ms35392088"
booking.com.            900     IN      TXT     "VkJHqtn1JPDHrgqwzb8C30fmoABFhxVfjIOtLvlUK06CUwKgd2mevDGtnDhWZcNbxEgK39DOezbHay8XSv1zVQ=="
booking.com.            900     IN      TXT     "ZOOM_verify_rRPrFA9oTH2bxfFkJeQTzA"
booking.com.            900     IN      TXT     "_globalsign-domain-verification=9Xqu2bonefjuoUF-XmyjAptAfuE-yStJz6wy9UnH-C"
booking.com.            900     IN      TXT     "_globalsign-domain-verification=FSlSaYMuHsffF-JRsSpJSonQOV0_jwrwl5kQGpFdtb"
booking.com.            900     IN      TXT     "_globalsign-domain-verification=l_BNpBAnk-rKZRyXJ9UkBfv9o6EEuuenkBrGpYNYo0"
booking.com.            900     IN      TXT     "adobe-idp-site-verification=040db58f-cfb9-4203-a555-bfcd15b24b86"
booking.com.            900     IN      TXT     "apple-domain-verification=immERz8LzjEgeSoW"
booking.com.            900     IN      TXT     "asv=93db973d8bc6fd37d0c9e0c3feebff95"
booking.com.            900     IN      TXT     "atlassian-domain-verification=F3hugs/a4ZZHwjGTLmlb12IMA3TIRiz3ifqw4TKRz9tWk0LoyBBXfwc775aT/juy"
booking.com.            900     IN      TXT     "atlassian-domain-verification=PEQekniknkTLbMzMw6Ifb9G9YWzhgcGHzIne34xYo7zW9/rzVsM/6qZSUWdIVAmR"
booking.com.            900     IN      TXT     "cisco-ci-domain-verification=45d8573a6620606f09d1556681408112c9f9754309b02423c380eee5d287bd8f"
booking.com.            900     IN      TXT     "docker-verification=0ebe0b8e-6bd1-4f94-b0b3-344bd07052ed"
booking.com.            900     IN      TXT     "docusign=1ddc2bf3-a249-4127-a351-f22dc75077d3"
booking.com.            900     IN      TXT     "ecostruxure-it-verification=881dfd3b-5776-4fc0-a5f6-190a0ac842f8"
booking.com.            900     IN      TXT     "f3n3z6cw35fkl9lnb6q72dczy2z7d2gy"
booking.com.            900     IN      TXT     "fastly-domain-delegation-0344411-343733-2021_0223"
booking.com.            900     IN      TXT     "globalsign-domain-verification=jpcnVg6kuHYyEz5op6ZzxI2E53gePoVqca7RgL0aNq"
booking.com.            900     IN      TXT     "google-site-verification=1eOMDGAH7nc_P5U-8MWPqSTU40og02u0CODDvbcmoMw"
booking.com.            900     IN      TXT     "google-site-verification=IqETr3m1Iq2apdhg2tJndtOH5xn_C0PrLSBL4UpB9WU"
booking.com.            900     IN      TXT     "google-site-verification=WMDRc5NQqj7RWff1N8L0_Ikc08kSr-iUa3C0Zczl9QA"
booking.com.            900     IN      TXT     "google-site-verification=Yse39yHdmcUPiSTGNVY-eI27sV3TBfQVLBPHGWHiins"
booking.com.            900     IN      TXT     "google-site-verification=_dm8lZJlohRuCXhYRFe8COWc0JNx7c6AVF1vWpP52nE"
booking.com.            900     IN      TXT     "google-site-verification=qKQzyXjxHLM4q1X-7PdrurR3p1QjjINz2QD_MBvAmyU"
booking.com.            900     IN      TXT     "google-site-verification=w40NMRtPNbdzr8FXV33gtkD3qlFHastApR2UgHgggf8"
booking.com.            900     IN      TXT     "google-site-verification=z4muhl35r1aT-msc5R269PO3RKaZHc7zzn6omxkiedI"
booking.com.            900     IN      TXT     "gwt5v1xngwj1f6zq7khv3bp4xnxbgmkg"
booking.com.            900     IN      TXT     "include:mail.zendesk.com"
booking.com.            900     IN      TXT     "intersight=f7b95d6ad5339839c1253d5e47c1c32ff8276909334ff7173890c54f4730e68a"
booking.com.            900     IN      TXT     "logmein-domain-confirmation 90DIFG9EEUT8U8R4895Y87H"
booking.com.            900     IN      TXT     "mandrill_verify.e-l764xQVEGJ2x07f-WGHg"
booking.com.            900     IN      TXT     "miro-verification=a08b425a7aa0b2b93256f4b504ee72afe8f9e0b9"
booking.com.            900     IN      TXT     "onetrust-domain-verification=3fce180bf9e54d5b97a7c9e1ce3cb10c"
booking.com.            900     IN      TXT     "sending_domain1012722=80cff31442c5f4e1b9c51346939d5bf298d9eff5f69d465476631c95f588ac90"
booking.com.            900     IN      TXT     "smartsheet-site-validation=zF2Qh0qhBS3O7AjSZMdaAVW2E7GB1VLL"
booking.com.            900     IN      TXT     "v=spf1 include:%{ir}.%{v}.%{d}.spf.has.pphosted.com -all"
booking.com.            900     IN      TXT     "wrike-verification=NDM5MTUzODoyMTFkNjJmZWM5MDk5MTVjOWY2YTQ2MWI4MmVhNjRkZjBmNjg3NzhmZTJhZTQ2NjYxMmVlNjNmMDJkZWRkN2Vi"
booking.com.            900     IN      TXT     "x9zcxt1dfyz6jj60w7smwl42tjzfv5yn"

;; Query time: 64 msec
;; SERVER: 8.8.8.8#53(8.8.8.8) (TCP)
;; WHEN: Wed May 01 22:33:07 IST 2024
;; MSG SIZE  rcvd: 3303

# Cloud Resources

We didnt find any s3 buckets or blob storage, or any other storage

however found some apps being hosted on `Azure App Service`, and aws resources like elb

┌──(kali㉿kali)-[~]
└─$ cat ip_addresses_by_domains.txt | grep azure  
`
┌──(kali㉿kali)-[~]
└─$ cat ip_addresses_by_domains.txt | grep aws  

┌──(kali㉿kali)-[~]
└─$ cat ip_addresses_by_domains.txt | grep s3  

┌──(kali㉿kali)-[~]
└─$ cat ip_addresses_by_domains.txt | grep blob