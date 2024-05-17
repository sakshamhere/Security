# Escape Notations

- \0    the NULL character
- \'    single quote
- \"    double quote
- \\    backslash
- \n    new line
- \r    carriage return
- \v    vertical tab
- \t    tab
- \b    backspace
- \f    form feed

A backslash before a character tells the JavaScript parser that the character should be interpreted literally as a normal string character, and not as a special character such as a string terminator or other.

# Techniques to call functions without parentheses.
https://portswigger.net/research/xss-without-parentheses-and-semi-colons

- using onerror and the throw statement

It works by setting the onerror handler to the function you want to call and the throw statement is used to pass the argument to the function:

<script>onerror=alert;throw 1337</script>

The onerror handler is called every time a JavaScript exception is created, and the throw statement allows you to create a custom exception containing an expression which is sent to the onerror handler. Because throw is a statement, you usually need to follow the onerror assignment with a semi-colon in order to begin a new statement and not form an expression.