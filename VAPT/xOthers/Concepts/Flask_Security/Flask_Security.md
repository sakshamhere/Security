Security Considerations

# XSS
1. 
{% autoescape false %}
{% endautoescape %}

you should never deactivate autoescaping in jinja/flask, so you should never have {% autoescape false %} in your production templates. This way you will always get the standard HTML context filtering for variables in your templates.

Flask uses Jinja2 template engine and Flask enables automatic escaping on Jinja2 by default.

If you really want to allow XSS, change {{ task.content }} to {{ task.content|safe }} on your template.

2. 
Another thing that is very important are unquoted attributes. While Jinja2 can protect you from XSS issues by escaping HTML, there is one thing it cannot protect you from: XSS by attribute injection

To counter this possible attack vector, be sure to always quote your attributes with either double or single quotes when using Jinja expressions in them:
<input value={{ value }}>  -->  <input value="{{ value }}">

3. 
There is one class of XSS issues that Jinja’s escaping does not protect against. The a tag’s href attribute can contain a javascript: URI, which the browser will execute when clicked if not secured properly.

<a href="{{ value }}">click here</a>
<a href="javascript:alert('unsafe');">click here</a>

To prevent this, you’ll need to set the Content Security Policy (CSP) response header.