https://www.freecodecamp.org/news/google-dorking-for-pentesters-a-practical-tutorial/


A Dorking Scenario

Let’s assume you have to conduct a pentesting audit for a client. Here is a sample dorking scenario.

Use the “site” operator to limit your search to the company’s website: site:example.com. This returns all pages on the example.com website.

Use the “intitle” operator to search for pages containing specific keywords in the title: intitle:”login” site:example.com. This helps identify potential login pages vulnerable to attack.

    Use the “filetype” operator to search for specific file types: filetype:pdf site:example.com. This helps identify potential documents or reports containing sensitive information.

    Use the “inurl” operator to search for specific URLs: inurl:”admin” site:example.com. This helps identify potential administrative pages vulnerable to attack.

    Use the “cache” operator to view the cached version of a webpage Google has indexed: cache:example.com/login.php. This provides access to the page contents even if the original page is removed or no longer accessible.
    
    Use the “related” operator to find similar websites: related:example.com. This helps identify potential partners or third-party vendors with access to the company’s network.

Summary

Google Dorking is a powerful technique that allows us to perform advanced searches on Google. We can use Google Dorks to find specific information and publicly exposed vulnerabilities. It is an essential tool in a pentester’s toolkit.

Google Hacking Database (GHDB) provides a collection of pre-defined Google Dorks. Given the harm that someone can cause using dorking, it is important to use it ethically and with permission. Ensure that you have permission and follow ethical guidelines when using dorking for security audits.