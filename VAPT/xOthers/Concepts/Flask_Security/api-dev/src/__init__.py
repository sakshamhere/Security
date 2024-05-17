from flask import Flask, jsonify
import os

def create_app(test_config=None):

    app = Flask(__name__, instance_relative_config=True)    # it tells app that we also have some other config to consider 

    if test_config is None:
        app.config.from_mapping(
            # SECRET_KEY="dev",
            SECRET_KEY=os.environ.get("SECRET_KEY"),

        )

    else:
        app.config.from_mapping(test_config)

    @app.route("/")
    def index():
        return "hello world"

    @app.route("/hello")
    def hello():
        return jsonify({"message":"hello world"})

    return app

