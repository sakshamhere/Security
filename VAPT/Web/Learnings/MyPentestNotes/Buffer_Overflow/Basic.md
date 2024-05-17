
# Anantomy of Memory

1111                            Kernel              TOP

                                Stack

                                Heap

                                Data
0000                            Text                BOTTOM

Its Kernel at the Top and Text at the Botton

Lets dive deeper into STACK

# Anatomy of the STACK

            ESP (Extended Stack Pointer)                   TOP


                    Buffer Space


            EBP (Extended Base Pointer)                    BOTTOM
    EIP (Extended Instruction Pointer) / Return Address    


Above menioned are registers ESP, EBP and EIP

Think about as ESP sitting at the TOP and EBP at Botton

So what happens is that we have this Buffer Space between EBP and EIP and this buffer space fills up with characters and it goes downard while getting filled

Ideally if this space starts filling up from TOP to Bottom it should stop at EBP

The Buffer Space should be able to contain the characters user is sending

Anatomy
            `ESP(ExtendedAStackAPointer)`                   `TOP`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAA`BufferASpace`AAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            `EBP(ExtendedABaseAPointer)`                   `BOTTOM`
    `EIP (Extended Instruction Pointer) / Return Address ` 



Now If you have a Buffer Overflow attack, then you overflow the Buffer Space and reach EBP and intercept EIP


Anatomy
            `ESP(ExtendedAStackAPointer)`                   `TOP`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAA`BufferASpace`AAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAA `EBP(ExtendedABaseAPointer)`AAAAAAAAAAAAAAAAAAA`BOTTOM`
AAAAA`EIP (Extended Instruction Pointer) / Return Address `A 


So If you are able to overflow Buffer and write all the way to EIP then you are able to control the STACK 

`The EIP is something intersting, this is a pointer address or we can saya return address, So we can use this to point to directions that we instruct,  these directions are going to be malicious code that gives us the Reverse shell`


***************************************************************

# Steps to conduct a Buffer Overflow

1. Spiking

It is the Method we use to find the vulnerable part of program

2. Fuzzing

Once we find vulnerable part we are going to fuzz it with bunch of characters and see if we can break it

3. Fuzzing the Offset

If we did break it, we need to find at what point we break it so we wanna find something called Offset

4. Overwriting the EIP

We use that Offset and try to overwrite the EIP and have control over EIP

5. Finding Bad Characters

We now have control over EIP, but before going forward to generate shellcode, we need to check for hex char which are bad char for programs, basically there are some char which can act to something in code and these type of character will ruin or break our shellcode we need to find and remove them

6. Finding the Right Module

When we say we are finding right module, we mean we need to inspect program's dll files to find a dll without memory protection

7. Generating Shellcode

We gona generate shellcode and point EIP to it and then trigger it gain Root!

8. Gaining Root!

**************************************************

Must Read 
https://vulp3cula.gitbook.io/hackers-grimoire/exploitation/buffer-overflow




