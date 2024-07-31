https://realpython.com/flask-connexion-rest-api/
# Dependencies

- Flask
- on top of Flask we need `Connexion` to handle the HTTP Requests.

# Connexion

The `Connexion module `allows a Python program to use the `OpenAPI` specification with `Swagger`. The OpenAPI Specification is an API description format for REST APIs and provides a lot of functionality, including:

    - Validation of input and output data to and from your API

    - Configuration of the API URL endpoints and the expected parameters

When you use OpenAPI with Swagger, you can create a user interface (UI) to explore the API

* All of this can happen when you create a configuration file that your Flask application can access

# API Configuration File

The Swagger .yml Configuration file is a YAML or JSON file containing your OpenAPI definitions. 

The .yml file is like a blueprint for your API. With the specifications that you include in .yml, you define what data your web server can expect and how your server should respond to requests. 

When you define an API, you must include the version of your OpenAPI definition. You use the openapi keyword for this. The version string is important because some parts of the OpenAPI structure may change over time. 

The info keyword begins the scope of the API information block:

`title`: Title included in the Connexion-generated UI system
`description`: Description of what the API provides or is about
`version`: Version value for the API

Next, add `servers` and `url`, which define the root path of your API

Then You define your API endpoints in a `paths` block

Then The `get/post/delete/put/patch` block begins the configuration of the single URL endpoint:

`operationId:` The Python function that’ll respond to the request
`tags`: The tags assigned to this endpoint, which allow you to group the operations in the UI
`summary`: The UI display text for this endpoint
`responses` : The status codes that the endpoint responds with

operationId must contain a string. for ex Connexion will use "people.read_all" to find a Python function named read_all() in a people module of your project. 


# Add Connexion to app

Two steps to adding a REST API URL endpoint to your Flask application with Connexion:

First add an API configuration file to your project. Then Connect your Flask app with the configuration file. you must reference .yml in your app.py file

Part of the app instance creation includes the parameter `specification_dir`. This tells Connexion which directory to look in for its configuration file.
Then you tell the app instance to read the .yml file from the specification directory and configure the system to provide the Connexion functionality.

# components

** Before you define new API paths in swagger.yml, you’ll add a new block for `components`. Components are building blocks in your OpenAPI specification that you can reference from other parts of your specification

components:
  schemas:
    Person:
      type: "object"
      required:
        - lname
      properties:
        fname:
          type: "string"
        lname:
          type: "string"


** The structure for `post` looks similar to the existing `get` schema. One difference is that you also send `requestBody `to the server.

# parameters
Similar to your /people path, you start with the get operation for the `/people/{lname} `path. The {lname} substring is a placeholder for the last name, which you have to pass in as a URL parameter. So, for example, the URL path api/people/Ruprecht contains Ruprecht as lname.

Note: The URL parameters are case sensitive. That means you must type a last name like Ruprecht with an uppercase R.

You’ll use the lname parameter in other operations, too. So it makes sense to create a component for it and reference it where needed.

# config.py
The config.py module is, as the name implies, where all of your configuration information is created and initialized. In this file, you’re going to configure Flask, Connexion, SQLAlchemy, and Marshmallow. 

# Vulnerabilities

# BOLA Broken Object level Authorization

