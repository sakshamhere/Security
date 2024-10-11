# OAuth 2.0 (Open Authorization)

OAuth 2.0 (Open Authorization) is an authorization protocol which allows websites to access user information from a third-party without making use of login credentials. OAuth makes use of Access Tokens to access resources on behalf of the user, these tokens are not having a fixed format but generally JSON web tokens (JWT) are used.
OAuth consist 3 parties:
`Client App` - Website that wants to access user’s data.
`Resource Owner` - User whose data app wants to access.
`Service Provider `- Third party website/app that controls user’s data.
OAuth uses two types of grant, “authorization code” and “implicit” grant type, both grant type involve following stages:
1. Client App requests user’s data by specifying one of the grant type.
2. The user is then prompted to log in to Service Provider.
3. Client App receives a unique access token, it uses it to fetch user’s details.

# Process for “Authorization Code” grant type:
Once a user logins service provider, client app is granted an “authorization code”, client app sends this code to the service provider to get an “access token”, which it can use for further API calls to fetch user data. All this communication happens at the back channel securely and no sensitive data is sent via browser, hence this grant type is best for server-side applications.
The client app sends a initial request to OAuth service with the following parameters.

`GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1`
Host: oauth-authorization-server.com
`Client_id` - unique identifier of client app, this is provided to client app when it was registered with OAuth service
`Redirect_uri` - the URI to which the user's browser should be redirected for the client to get authorization code.
`Response_type` - determines what type of response client is expecting, for authorization code it should be “code”.
`Scope` - It includes a subset of users data that the client wants from the service provider.
`State` - It is a unique value tied to the current session of client application, it serves as a CSRF token making sure that request is from the same person who initiated OAuth flow.

After the initial request user is provided login for his social media account, the user will be presented with the scope (data) that client app wants to access, if user gives consent the browser will be redirected to redirect_uri and the callback will contain authorization code.

GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1
Host: client-app.com
Once client app receives code it will send it to service provider to get access_token, it sends a POST request to /token.
POST /token HTTP/1.1
Host: oauth-authorization-server.com
…
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8

This request will include client_secret (this was assigned to client app while being registered for OAuth service).
`All communication from this point will be in a secure back channel `and cannot be observed or controlled by browser and attacker. The OAuth server will then verify the access token request and if its valid then will send access_token.
{
    "access_token": "z0y9x8w7v6u5",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "openid profile",
    …
}

Now the client app has access_token and it can use it to fetch the scope data from service providers using API calls. 

# Process for “Implicit” grant type:
In this instead of obtaining a authorization code and then using it to get acces_token is not done, in this grant type client app immediately receives access_token after users consent through browser, In this `all communication happens through browser and is very less secure as no back channel like flow is there like authorization code grant type.`
This grant type is suitable for single page application and  desktop application which does not store client_secret at backend.
