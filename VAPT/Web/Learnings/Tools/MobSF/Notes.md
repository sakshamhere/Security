https://x.com/Jayesh25_/status/1727971399141089668?s=20

# mobsf.live. - https://t.co/CzW6stNqdG

The best part? You can try it out without installation! Experience MobSF directly at https://mobsf.live. If you prefer to install and run your own local version, you can do so via `https://github.com/MobSF/Mobile-Security-Framework-MobSF.`

While MobSF offers a range of features, here's the list of things I use it for:

📥 `Easy to use:` Easily analyze your APK with straightforward drag-and-drop functionality, eliminating the need for multiple tool installations. This is specifically good for beginners because they don't have to rely on complex installation of 5 different tools for testing an app

🔑 `Identifying Hardcoded Secrets:` The tool helps flag hardcoded credentials, aiding in validation and reporting. I've had some quick wins through this module with sensitive tokens/API keys disclosed 

☕ `Reviewing Java Source Code:` I mostly use it to examine Java source code for my target, uncovering API endpoints, design flaws, or reverse engineering possibilities to overcome jailbreak detection, etc..

🕵️ `Reverse Engineering:` It helps with reverse engineering, including de-compilation, disassembly, and debugging.

🔄 `Dynamic Analysis:` It Integrates with Genymotion to inspect HTTP traffic while navigating through the app, effectively detecting endpoints. I use it at times to get a quick Idea of what HTTP calls are being made when Initially navigating through my target

It's worth noting that I still use other tools like Burp Suite, MITM, and Charles Proxy. However, I usually run my target apps through MobSF first as It gives me a nice overview of the target and some quick wins.