import json
import yaml

def convert_postman_to_openapi(postman_file_path, output_file_path):
    # Load Postman collection JSON
    with open(postman_file_path, 'r') as f:
        postman_collection = json.load(f)

    # Initialize OpenAPI structure
    openapi_spec = {
        "openapi": "3.0.0",
        "info": {
            "title": postman_collection["info"]["name"],
            "description": postman_collection["info"].get("description", ""),
            "version": "1.0.0"
        },
        "paths": {},
        "components": {
            "schemas": {}
        }
    }

    # Process each item in Postman collection
    for item in postman_collection.get("item", []):
        process_item(item, openapi_spec["paths"])

    # Write the OpenAPI specification to a YAML file
    with open(output_file_path, 'w') as f:
        yaml.dump(openapi_spec, f, sort_keys=False)
    print(f"OpenAPI spec saved to {output_file_path}")

def process_item(item, paths):
    """
    Recursive function to process each item (endpoint) in the Postman collection.
    Handles both folders (groups of requests) and individual requests.
    """
    if 'item' in item:
        # Folder/group of requests
        for sub_item in item["item"]:
            process_item(sub_item, paths)
    else:
        # Individual request
        url = item["request"]["url"]
        method = item["request"]["method"].lower()
        path = build_path(url)
        
        # Define path if not already defined
        if path not in paths:
            paths[path] = {}
        
        # Extract request description, headers, and parameters
        request_description = item["request"].get("description", "")
        headers = item["request"].get("header", [])
        parameters = get_parameters(headers, url)
        
        # Extract response schemas if available
        responses = {
            "200": {
                "description": "Successful response"
            }
        }
        
        # Add request details to OpenAPI path
        paths[path][method] = {
            "summary": item["name"],
            "description": request_description,
            "parameters": parameters,
            "responses": responses
        }

def build_path(url):
    """
    Convert Postman URL to OpenAPI path format.
    """
    # Example: https://api.example.com/users/:id -> /users/{id}
    path = "/".join([
        f"{{{part[1:]}}}" if part.startswith(":") else part
        for part in url.get("path", [])
    ])
    return f"/{path}"

def get_parameters(headers, url):
    """
    Convert Postman headers and query parameters to OpenAPI parameters format.
    """
    parameters = []
    
    # Add headers
    for header in headers:
        parameters.append({
            "name": header["key"],
            "in": "header",
            "required": not header.get("disabled", False),
            "schema": {
                "type": "string"
            },
            "description": header.get("description", "")
        })
    
    # Add query parameters
    for query_param in url.get("query", []):
        parameters.append({
            "name": query_param["key"],
            "in": "query",
            "required": not query_param.get("disabled", False),
            "schema": {
                "type": "string"
            },
            "description": query_param.get("description", "")
        })
    
    return parameters

# Replace with your input Postman collection and desired output OpenAPI file path
postman_file_path = "path/to/your_postman_collection.json"
output_file_path = "path/to/output_openapi.yaml"
