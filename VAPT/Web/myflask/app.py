from flask import Flask, redirect, url_for

app = Flask(__name__)

@app.route("/")
def home():
    return "hey"

@app.route("/<RXSS>")
def R_XSS(RXSS):
    return f"hello {RXSS}c"

@app.route("/SXSS")
def S_XSS():
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run()