
# Advantages of GraphQL and reasons to use it.

 - ` One Endpoint `

 With traditional REST APIs, you have to create specific endpoints based on the data you want to request. This makes scaling your API difficult because soon, you might find yourself having to manage tens, maybe hundreds, of routes that you will have to remember.

- ` Fewer server requests `

GraphQL allows you to make multiple queries and mutations with only one server request. This can be useful when your server only allows a limited number of requests a day.

- `Declarative data fetching:`

Unlike a REST API, GraphQL only fetches what you actually need. All you have to do is specify what fields to return.

- ` Type system `

GraphQL uses a type system to describe your data, which makes developing much easier. If you are a TypeScript fan, this is a win-win.

- ` Self-documenting `

GraphQL is self-documenting, meaning that all of your queries and mutations will automatically be documented by GraphQL.


One of the basic problems with conventional REST is the failure of the client to demand a personalized data set. In addition to that, running and controlling multiple endpoints is another difficulty as clients are mostly needed to request data from diversified endpoints.

While establishing a GraphQL server, `it’s only important to have single URL for complete data procurement and alteration.` Therefore, a user can request a dataset from a server by transferring a query string, mentioning what they need.