from flask import Flask, redirect, url_for, request, render_template, make_response

app = Flask(__name__)



@app.route('/', methods=['GET','POST']) 
def XSS():
    search_query = request.args.get('q')
    if search_query:
        # search_query = search_query.lower()
        search_query = search_query.replace("<script>","")

        # import re
        # search_query = re.sub(r"[script</?\[\d+>]", "", search_query)
        # search_query = re.sub(r"[</script>]", "", search_query)

        # search_query = search_query.replace('&','&amp;')
        # search_query = search_query.replace('<','&lt;')
        # search_query = search_query.replace('>','&gt;')
        # search_query = search_query.replace('"','&quot')
        # search_query = search_query.replace("'",'&#x27')
        # search_query = search_query.replace("'",'&#x2F')

    return render_template('index.html', search_query=search_query)

# @app.after_request
# def add_header(make_response):
#     make_response.headers['X-Frame-Options'] = 'SAMEORIGIN'
#     make_response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline';"
#     return make_response

# Q - display curr date in dd/mm/yy in document.write in this reflected XSS

#possible bypass
#- if case not changed <sCript>alert(1)</sCript>
# to print date use Date() <sCript>document.write(Date())</sCript>  ==> Hello Tue Dec 13 2022 14:10:54 GMT+0530 (India Standard Time)

# <sCript>
# var today = new Date();
# var dd = String(today.getDate()).padStart(2, '0');
# var mm = String(today.getMonth() + 1).padStart(2, '0');
# var yyyy = today.getFullYear();
# today = mm + '/' + dd + '/' + yyyy;
# document.write(today);
# </sCript>


if __name__ == "__main__":
    app.run()


# XSS payload
# <script>alert(1)</script>
# <sCript>alert(1)</sCript>
# <img src=1 onerror=alert(1)>  onmouseover
# <svg/onload=alert('XSS')>
# <BODY ONLOAD=alert('XSS')>


# "javascript:alert('unsafe');"
# javascript:alert('unsafe');



    # @app.route("/")
# def home():
#     return "hey"

# @app.route("/<RXSS>")
# def R_XSS(RXSS):
#     return f"hello {RXSS}c"

# @app.route("/SXSS")
# def S_XSS():
#     return redirect(url_for("home"))