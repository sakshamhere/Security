from datetime import datetime
from flask import abort, jsonify, Response, request, json

def get_timestamp():
    return datetime.now().strftime(("%Y-%m-%d %H:%M:%S"))

def error_message_helper(msg):
    return '{ "status": "fail", "message": "' + msg + '"}'

def success_message_helper(msg):
    return '{ "status": "pass", "message": "' + msg + '"}'
PEOPLE = {
    "Fairy": {
        "fname": "Tooth",
        "lname": "Fairy",
        "timestamp": get_timestamp(),
    },
    "Ruprecht": {
        "fname": "Knecht",
        "lname": "Ruprecht",
        "timestamp": get_timestamp(),
    },
    "Bunny": {
        "fname": "Easter",
        "lname": "Bunny",
        "timestamp": get_timestamp(),
    }
}


def read_all():
    return list(PEOPLE.values())

def read_one(lname):
    if lname in PEOPLE:
        return PEOPLE[lname]
    else:
        abort(
            404, f"Person with last name {lname} not found"
        )

def create(person):

    lname = person.get("lname")
    fname = person.get("fname", "")

    if lname and lname not in PEOPLE:
        PEOPLE[lname] = {
            "lname": lname,
            "fname": fname,
            "timestamp": get_timestamp(),
        }
        responseObject = {
           
            'details':{
                "lname": lname,
                "fname": fname,
                "timestamp": get_timestamp(),
            },
            'message':'The user has been created',
            'status':'Success'
        }
        #return PEOPLE[lname]
        #return Response(json.dumps(PEOPLE[lname]), 201, mimetype="application/json")
        return Response(json.dumps(responseObject), 201, mimetype="application/json")
    else:
        abort(                  #Using abort() helps you send an error message
            406,
            f"Person with last name {lname} already exists",
        )

def update(lname,person):
    
    if lname in PEOPLE.keys():
        PEOPLE[lname]['fname']=person.get('fname'),
        PEOPLE[lname]['timestamp'] = get_timestamp()
        return PEOPLE[lname]
    else:
        return Response(error_message_helper("User does not exist"), 404, mimetype="application/json")

def delete(lname):
    if lname in PEOPLE.keys():
        del PEOPLE[lname]
        return Response(success_message_helper("User deleted"),200,mimetype="application/json")
    else:
        return Response(error_message_helper("User does not exist"), 404, mimetype="application/json")