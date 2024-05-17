# Finding Bad characters

So When we are generating shellcode we need to know what characters are good for the shellcode and what characters are bad for the shellcode

fo example character x70,  then there might be some code in our vulnerable program which might act to this character

So we dont want to include such characters in our shellcode, becuse then our shellcode will break

We can check this by running all the bad Hex characters through our program and see if any of them acts up

Note we know already that By defult the null byte x00 acts up so will remove it before only



# Lets just take all hex chars from `\x00 to \xff` and check for  badchars for this program
https://github.com/cytopia/badchars

Note we know already that By defult the null byte x00 acts up so will remove it before only

"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"


# We can paste this in our script (check fuzz4.py) and we can simply remove null char X00 as we alredy know that this acts up

# let give fuzz4.py execute permission and run it

┌──(kali㉿kali)
└─$ `./fuzz4.py `

# Right click on ESP and click follow dump, now check the Hex dump in left bottom in immunity debugger

# Luckily vulnserver is made easy and so we dont have any bad char to be found

# Lets now find right module


*******************************************
Read To get more idea on bad char removal
- https://medium.com/@notsoshant/windows-exploitation-dealing-with-bad-characters-quickzip-exploit-472db5251ca6

https://www.reddit.com/r/oscp/comments/e7ju33/finding_bad_characters_for_linux_buffer_overflows/

# Some good comments to understand!

It’s precisely the same process as is used with immunity debugger, just send a buffer filled with every `hex value` from `0x00 to 0xff` and review the area of memory your buffer is loaded into.

When running your exploit, have a large block of all characters from `\x00 to \xff`. Analyze process memory and determine which ones are mangled, removed, or end your buffer, or otherwise corrupt it. Write those down. Remove them from the buffer and send it again until the rest of the payload is exactly like it was sent. The characters you wrote down/removed from the buffer are your bad characters. 

In my case, i always have a .txt file with all `Hex Char` from `\x00 to \xff`. Simply just send a buffer filled with your list of all hex chars and then start to analyze the buffer. 