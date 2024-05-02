
# yield https://www.youtube.com/watch?v=bD05uGo_sVI

* yield - This keyword is used like return statement but is used to return a generator.

Basically yield instead of returning resultant value it returns the current value which we can get though next() also

generators are useful as they dont hold all value in memory hence when we need to loop though thousands of value this makes good performance

A generator-function is defined like a normal function, but whenever it needs to generate a value, it does so with the yield keyword rather than return. If the body of a def contains yield, the function automatically becomes a generator function. 

# Global,global keyword and Nonlocal
* global: This keyword is used to define a variable inside the function to be of a global scope.

* global keyword: you can access global var inside a fun, but you cant modify it in there to do so you need to use gloabl keyword

Note: we can modify list elements defined in global scope without using global keyword. Because we are not modifying the object associated with the variable arr, but we are modifying the items the list contains

If we are trying to assign a new list to the global variable. Then, we need to use the global keyword

* non-local : This keyword works similar to the global, but rather than global, this keyword declares a variable to point to variable of outside enclosing function, in case of nested functions.

# Frozeen set 
Set is an unordered collection of data types that is iterable, mutable and has no duplicate elements

Frozen sets in Python are immutable objects that only support methods and operators that produce a result without affecting the frozen set or sets to which they are applied. While elements of a set can be modified at any time, elements of the frozen set remain the same after creation. 

# Decorators

In Decorators, functions are taken as the argument into another function and then called inside the wrapper function.

# Python Subprocess check_output()
https://data-flair.training/blogs/python-subprocess-module/#:~:text=Python%20Subprocess%20check_output(),code%20in%20the%20returncode%20attribute.

This function runs the command with the arguments and returns the output.

So far, the output was bound to the parent process and we couldn’t retrieve it.

For a non-zero return code, it raises a CalledProcessError which has the return code in the returncode attribute.

1. Syntax
It has the following syntax-

subprocess.check_output(args, *, stdin=None, stderr=None, shell=False, cwd=None, encoding=None, errors=None, universal_newlines=False, timeout=None)

Examples
Now, the example of Python Subprocess check_output

>>> subprocess.check_output(["echo","Hello World!"],shell=True)
Output

b'”Hello World!”\r\n’

# Logging in python
https://realpython.com/python-logging/