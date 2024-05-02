# SSRF   Bypass SSRF protection with different encodings.
https://x.com/thebinarybot/status/1447172304463564806?s=20

# Where to find SSRF Issues?
https://x.com/Jayesh25_/status/1723270079444402561?s=20

These are the top 5 obvious features I look for in a target app to find SSRF Issues:

# 1️⃣ Export to PDF - 
Does your target app support generating PDFs? 📄 Try injecting HTML into the content that is used for generating that PDF. If vulnerable to HTML injection, you might strike gold by injecting HTML/JS.💰

# 2️⃣ Integrations - 
If your target app supports web hook Integration feature, replace the URL with your Burp Collab and wait for a hit. 🔄

# 3️⃣ Import via link Feature - 
Does your target app support importing files or websites via a link? 📥 Specify your attacker Burp Collab and check for a hit, especially when uploading profile pictures or media through a library.

# 4️⃣ Host Header - 
Test for Routing-based SSRF by supplying your Collaborator server domain in the Host header. If you receive a DNS lookup from the target server, you might be able to route requests to arbitrary domains🌐

# 5️⃣ File Upload - 
Does your target app support uploading files? 📂 Try uploading an HTML file; if rendered and executed on the server-side, you might strike gold. No luck? Try an SVG with SSRF payload. If that fails, move on to the next!