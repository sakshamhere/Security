// variables
// - let
// - const 
// - var (this is not used anymore)

let message;

message = "helllow buahui"

// The string is now saved into the memory area associated with the variable. We can access it using the variable name:

alert(message)

//we can combine the variable declaration and assignment into a single line:

let message1 = 'Hello!'; // define the variable and assign the value

alert(message1); // Hello!

//We can also declare multiple variables in one line:

let user = 'John', age = 25, message3 = 'Hello';

//The multiline variant is a bit longer, but easier to read:

let user2 = 'John';
let age2 = 25;
let message4 = 'Hello';

// Or even in the “comma-first” style:

let user3 = 'John'
  , age4 = 25
  , message6 = 'Hello';

// Technically, all these variants do the same thing. So, it’s a matter of personal taste and aesthetics.


const myname = "saksham"

// myname = "doshi"  

// Uppercase constants

const COLOR_ORANGE = "#FF7F00";

// ...when we need to pick a color
let color = COLOR_ORANGE;
alert(color); // #FF7F00

//  capital-named constants are only used as aliases for “hard-coded” values.


onclick='returnUrl = /url=(https?:\/\/.+)/.exec(location); 
        if(returnUrl)
          location.href = returnUrl[1];
        else 
          location.href = "/"'