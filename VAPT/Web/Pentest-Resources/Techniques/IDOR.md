
# IDOR in UUID:

# 1️⃣ Sign Up and Forgot Password Page: 
If you've discovered a service reliant on a user's account UUID, try signing up or using forgot password with a victim's email. The server might leak the UUID in the error response, e.g., "Error": "User Already Registered." "ID: "UUID" or "Message": "Verification Email Sent" "ID: "UUID"

# 2️⃣ Intentionally Exceed Rate Limits on Login: 
Deliberately trigger more user-specific errors by exceeding rate limits. Sometimes, server-side functions expose the UUID in responses. For instance, failing multiple login attempts may reveal the UUID when the response mentions an account lockout, e.g., "Error": "User Account Locked Out." "ID: "UUID"

# 3️⃣ User-Interactive Features: 
Keep an eye out for features like Add Friend, Search User, Chat, Invite User, or Follow User. These often enable you to interact with other users, and as a result, the UUID of the user might be exposed in responses.

# 4️⃣ Archived URLs with Unpredictable IDs: 
Explore leaked unpredictable IDs using Wayback, Waymore, or use Google Dorking to hunt for archived links or URLs related to the target app

# 5️⃣ Target Apps with Multiple Roles: 
If your target app supports multiple roles (e.g., Admin, Team Member), and you've identified improper access control issues, you're in luck. Team members within the same organization might have access to all target app components, along with the UUIDs within the same tenant. Make sure to highlight this in your report.

# 6️⃣Predictable Patterns: 
Are you kidding me? No, I am not. I've worked on target apps that had predictable ID patterns. People Ignore these patterns cause the moment someone sees complex IDs, they tend to get nervous. However, It is important that you generate multiple IDs on the object you're working on and make note of the ID patterns. I've noticed patterns like 3fd537eea0e7d425943be204, which at a glance looks complex. But I generated a couple of more e.g. 3fd537eea0e7d425943be121, 3fd537eea0e7d425943ba404, 3fd537eea0e7d425943be934.. Doesn't look complex anymore, does it?

# 7️⃣ Search Your Own Unpredictable UUIDs/Hashes: 
Look for your own UUID / Unpredictable ID in your Burp Suite HTTP Traffic for additional requests/responses where these IDs are inadvertently leaked. You may end up finding a request that can be used for accessing other user's UUIDs too.

