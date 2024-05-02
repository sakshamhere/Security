from flask import Flask, redirect, url_for, request, render_template, make_response, flash

import sqlite3


app = Flask(__name__)
app.config['SECRET_KEY'] = '123aa8a93bdde342c871564a62282af857bda14b3359fde95d0c5e4b321610c1'

@app.route('/xss', methods=['GET','POST']) 
def XSS():
    search_query = request.args.get('q')
    # if search_query:

# Solution - Input Validation , replace, use regex to replace all unwanted

        # search_query = search_query.lower()
        # search_query = search_query.replace("<script>","")

        # import re
        # search_query = re.sub(r'["</?\[\d+>]', "", search_query)
        # search_query = re.sub(r"[</script>]", "", search_query)

# Solution - Output (HTML) Encoding 

        # search_query = search_query.replace('&','&amp;')
        # search_query = search_query.replace('<','&lt;')  
        # search_query = search_query.replace('>','&gt;')
        # search_query = search_query.replace('"','&quot')
        # search_query = search_query.replace("'",'&#x27')
        # search_query = search_query.replace("'",'&#x2F')

    return render_template('xss.html', search_query=search_query)



@app.after_request
def add_header(make_response):
    make_response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # enabling below header dosent allow XSS
    # make_response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline';"

    return make_response

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

# XSS payload
# <script>alert(1)</script>
# <sCript>alert(1)</sCript>
# <img src=1 onerror=alert(1)>  onmouseover
# <svg/onload=alert('XSS')>
# <BODY ONLOAD=alert('XSS')>


# "javascript:alert('unsafe');"
# javascript:alert('unsafe');


@app.route('/', methods=['GET', 'POST'])
def SQLi():
    con = sqlite3.connect("db_users.sqlite")
    c = con.cursor()
    val = False
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')
        
        user = c.execute("SELECT * FROM users WHERE username = '{}' and password = '{}'".format(username, password)).fetchone()        
        if user:
            val = "Success"
        else:
            val = "invalid usernam and pass"

    return render_template('SQLi.html',val=val)
 



if __name__ == "__main__":

    app.run()






    # @app.route("/")
# def home():
#     return "hey"

# @app.route("/<RXSS>")
# def R_XSS(RXSS):
#     return f"hello {RXSS}c"

# @app.route("/SXSS")
# def S_XSS():
#     return redirect(url_for("home"))