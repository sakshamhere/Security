// Interaction: 
// - alert, prompt, confirm

alert("alert")

// Prompt

// The function prompt accepts two arguments:

// Syntex - result = prompt(title, [default]);

// It shows a modal window with a text message, an input field for the visitor, and the buttons OK/Cancel.

// title - The text to show the visitor.
// default - An optional second parameter, the initial value for the input field.

//The square brackets around default in the syntax above denote that the parameter is optional, not required.

// The visitor can type something in the prompt input field and press OK. Then we get that text in the result

result = prompt("do you really want to quit",['NO'])

console.log(result)

// Confirm

// The syntax:

// result = confirm(question);
// 
// The function confirm shows a modal window with a question and two buttons: OK and Cancel.
// The result is true if OK is pressed and false otherwise.

let isBoss = confirm("Are you the boss?");

alert( isBoss ); // true if OK is pressed