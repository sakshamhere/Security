
"use strict"

// function declaration
// function expression
// callback functions


// function declaration

function showMessage(){
    alert("hello")
}

showMessage()


function newMessage(from,text){

    alert(from+" "+text)
}

newMessage("hello","brother")

function newMessage1(from,text="brother2"){
    
    alert(from+" "+text)
}

newMessage1("hello")

function newfunction(){
    return "brother3"
}

function newMessage2(from,text=newfunction()){
  
    alert(from+" "+text)
}

newMessage2("Hello")

function newMessage3(from,text){

    // if (text === undefined) {
    //     text = 'unknown';
    //   }
    text = text || 'unknown';
    // text = text ?? "unknown";
    alert(from+" "+text)
}

newMessage3("hello")


// It is possible to use return without a value. That causes the function to exit immediately.

function myfun(param){
    if(param == undefined)
    return

    alert(param)
}

myfun("Hello")

// An empty return is also the same as return undefined:

console.log(myfun())




// FUNCTION EXPRESSION

// There is another syntax for creating a function that is called a Function Expression.

function sayHi() {
    alert( "Hello" );
  }

let sayHi1 = function() {    //Uncaught SyntaxError: Identifier 'sayHi' has already been declared (at 5.functions.js:74:5)
    alert( "Hello" );
  };

//   Here we can see a variable sayHi getting a value, the new function, created as function() { alert("Hello"); }.
  
//   As the function creation happens in the context of the assignment expression (to the right side of =), this is a Function Expression.
  
//   Please note, there’s no name after the function keyword. Omitting a name is allowed for Function Expressions.


// FUNCTION IS A VALUE

// Let’s reiterate: no matter how the function is created, a function is a value. Both examples above store a function in the sayHi variable.

// We can even print out that value using alert:

alert(sayHi); // shows the function code

// We can copy a function to another variable:

function sayHi() {   // (1) create
  alert( "Hello" );
}

let func = sayHi;    // (2) copy

func(); // Hello     // (3) run the copy (it works)!
sayHi(); // Hello    //     this still works too (why wouldn't it)

// CALLBACK FUNCTIONS

function ask(question, yes, no) {
    if (confirm(question)) yes()
    else no();
  }
  
  function showOk() {
    alert( "You agreed." );
  }
  
  function showCancel() {
    alert( "You canceled the execution." );
  }
  
  // usage: functions showOk, showCancel are passed as arguments to ask
  ask("Do you agree?", showOk, showCancel);

// The arguments showOk and showCancel of ask are called callback functions or just callbacks.

// The idea is that we pass a function and expect it to be “called back” later if necessary. In our case, showOk becomes the callback for “yes” answer, and showCancel for “no” answer.

// We can use Function Expressions to write an equivalent, shorter function:


// function ask(question, yes, no) {
//   if (confirm(question)) yes()
//   else no();
// }

// ask(
//   "Do you agree?",
//   function() { alert("You agreed."); },
//   function() { alert("You canceled the execution."); }
// );

// Here, functions are declared right inside the ask(...) call. They have no name, and so are called anonymous. Such functions are not accessible outside of ask (because they are not assigned to variables), but that’s just what we want here.


// In strict mode, when a Function Declaration is within a code block, it’s visible everywhere inside that block. But not outside of it.


// If we use Function Declaration, it won’t work as intended:

/*
let age = prompt("What is your age?", 18);

// conditionally declare a function
if (age < 18) {

  function welcome() {
    alert("Hello!");
  }

} else {

  function welcome() {
    alert("Greetings!");
  }

}

// ...use it later
welcome(); // Error: welcome is not defined

*/

// That’s because a Function Declaration is only visible inside the code block in which it resides.

// What can we do to make welcome visible outside of if?

// The correct approach would be to use a Function Expression and assign welcome to the variable that is declared outside of if and has the proper visibility.


let age = prompt("What is your age?", 18);

let welcome;

if (age < 18) {

  welcome = function() {
    alert("Hello!");
  };

} else {

  welcome = function() {
    alert("Greetings!");
  };

}

welcome(); // ok now


// Or we could simplify it even further using a question mark operator ?:

// let age = prompt("What is your age?", 18);

// let welcome = (age < 18) ?
//   function() { alert("Hello!"); } :
//   function() { alert("Greetings!"); };

// welcome(); // ok now


// Function Declarations are processed before the code block is executed. They are visible everywhere in the block.
// Function Expressions are created when the execution flow reaches them.