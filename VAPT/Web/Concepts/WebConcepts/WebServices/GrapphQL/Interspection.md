https://graphql.org/learn/introspection/

# Interospection Queries

useful to ask a GraphQL schema for information about what queries it supports. 

`__schema`

we can ask GraphQL, by querying the __schema field, 

{
  __schema {
    types {
      name
    }
  }
}