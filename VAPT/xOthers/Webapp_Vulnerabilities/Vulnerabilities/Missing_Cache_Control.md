# How cache control is generally implemented

1. Using Header

2. Using Meta tag

<meta http-equiv-"Cache-Control" content="no-cache">

# How to test in browser if response is cahced

If you want to check if your Cache-Control is working, dont jusy reload the page in your browser, but click in address box and hit enter with network tab open and check response code

if you see a status code of 200 it means that your page is not cached but loaded again, if you get a 304 it means it shoold be taking from cache