
https://github.com/OJ/gobuster


Tool is used to brute force


Available Modes

    dir - the classic directory brute-forcing mode
    dns - DNS subdomain brute-forcing mode
    s3 - Enumerate open S3 buckets and look for existence and bucket listings
    gcs - Enumerate open google cloud buckets
    vhost - virtual host brute-forcing mode (not the same as DNS!)
    fuzz - some basic fuzzing, replaces the FUZZ keyword
    tftp - bruteforce tftp files


ex

gobuster -u http://fakebank.com -w wordlist.txt dir