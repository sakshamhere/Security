// Maths
// The following math operations are supported:

// Addition +,
// Subtraction -,
// Multiplication *,
// Division /,
// Remainder %,
// Exponentiation **.

// String concatenation with binary +

// Usually, the plus operator + sums numbers.But, if the binary + is applied to strings, it merges (concatenates) them:

// Chaining assignments
//Another interesting feature is the ability to chain assignments:

let a, b, c;

a = b = c = 2 + 2;

alert( a ); // 4
alert( b ); // 4
alert( c ); // 4

//Chained assignments evaluate from right to left. First, the rightmost expression 2 + 2 is evaluated 
//and then assigned to the variables on the left: c, b and a. At the end, all the variables share a single value.


// Increment/decrement
// Increment ++ increases a variable by 1:

let counter1 = 2;
counter1++;        // works the same as counter = counter + 1, but is shorter
alert( counter1 ); // 3
// Decrement -- decreases a variable by 1:

let counter = 2;
counter--;        // works the same as counter = counter - 1, but is shorter
alert( counter ); // 1


// Bitwise operators
// Bitwise operators treat arguments as 32-bit integer numbers and work on the level of their binary representation.

// These operators are not JavaScript-specific. They are supported in most programming languages.

// The list of operators:

// AND ( & )
// OR ( | )
// XOR ( ^ )
// NOT ( ~ )
// LEFT SHIFT ( << )
// RIGHT SHIFT ( >> )
// ZERO-FILL RIGHT SHIFT ( >>> )

// Strict equality ===
// A regular equality check == has a problem. It cannot differentiate 0 from false:

// A strict equality operator === checks the equality without type conversion.

// In other words, if a and b are of different types, then a === b immediately returns false without an attempt to convert them.

alert( 0 === false ); // false, because the types are different


// For a strict equality check ===
// These values are different, because each of them is a different type.

alert( null === undefined ); // false
// For a non-strict check ==
// There’s a special rule. These two are a “sweet couple”: they equal each other (in the sense of ==), but not any other value.

alert( null == undefined ); // true


// The nullish coalescing operator ??

// The nullish coalescing operator ?? provides a short way to choose the first “defined” value from a list.

// It’s used to assign default values to variables:
let height;
// set height=100, if height is null or undefined
height = height ?? 100;

console.log(height)