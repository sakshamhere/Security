// There’s another very simple and concise syntax for creating functions, that’s often better than Function Expressions.

// It’s called “arrow functions”, because it looks like this:


// let func = (arg1, arg2, ..., argN) => expression;

// This creates a function func that accepts arguments arg1..argN, then evaluates the expression on the right side with their use and returns its result.

// Let’s see a concrete example:

let sum = (a, b) => a + b;

/* This arrow function is a shorter form of:

let sum = function(a, b) {
  return a + b;
};
*/

alert( sum(1, 2) ); // 3