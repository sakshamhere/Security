// data types

// 1 Number
// 2 BigInt 
// 3 String 
// 4 Boolean 
// 5 null
// 6 The "Undefined"
// 7 symbol
// 8 object         this is one non-primitive one

let a = 0;
let b = 10n;
let c = true;
let d = "foo";
let e = Symbol("id");
let f = null;
let g = undefined;
let h = alert;

let arr = [a,b,c,d,e,f,g,h]

for(let i=0; i<arr.length;i++){
    console.log(typeof(arr[i]))
}

