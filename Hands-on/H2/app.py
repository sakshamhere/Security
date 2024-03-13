import flask

app = flask.Flask(__name__)

@app.route('/',methods=['GET'])
def home():
    return "<h1>This is my flask app</h1>"

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0") # debug mode and localhost