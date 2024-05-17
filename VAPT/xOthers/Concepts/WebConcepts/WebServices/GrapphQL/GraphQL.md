https://www.youtube.com/watch?v=yWzKJPw_VzM&pp=ygUHZ3JhcGhxbA%3D%3D

While SQL is a query language for managing relational databases, GraphQL is a query language that allows the client (frontend) to request data from an API.


GraphQL provides a schema of data in API which allows and gives client power to ask exactly what he want.


` So if we want to fetch something from GraphQL server then we `query`, and if we want to provide something to it then we do `mutation` `

Mutation  - to add/Modify new data

# Query to fetch all pets

query GetAllPetes{
    pets {
        name
        type
    }
}

# Add a new pet (Mutation)

mutation Addnewpet ($name )