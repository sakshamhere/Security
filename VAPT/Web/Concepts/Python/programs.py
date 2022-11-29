// yield

def fun():
    S = 0
     
    for i in range(10): 
        print(i,'sa')
        S += i
        yield S
        
 
for i in fun():
    print(i)

// global and nonlocal

# global variable
a = 15
b = 10
 
# function to perform addition
def add():
    c = a + b
    print(c)
 
# calling a function
add()
 
# nonlocal keyword
def fun():
    var1 = 10
 
    def gun():
        # tell python explicitly that it
        # has to access var1 initialized
        # in fun on line 2
        # using the keyword nonlocal
        nonlocal var1
         
        var1 = var1 + 10
        print(var1)
 
    gun()
fun()

// froxenset
String = ('G', 'e', 'e', 'k', 's', 'F', 'o', 'r')
 
Fset1 = frozenset(String)
print("The FrozenSet is: ")
print(Fset1)
