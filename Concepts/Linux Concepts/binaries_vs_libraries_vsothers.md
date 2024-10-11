Before Binary and libraries we should know what is Object file

`Object files: ` 

These are natively compiled machine code, but may not even run or be callable. They `typically have a .o extension `unless they fall into one of the other categories, and are almost never seen on most systems except when building software.

*******************************

# `Binary / Executables`

'binary' refers to something that isn't human readable. This usually refers to machine code, but many other files are also binary files in this sense, with most multimedia formats being a good example.

These are files consisting of mostly self contained code that can be run directly. They may be either specially formatted object files which can be loaded directly by the kernel (things like `cat`, `bash`, and `python` are all this type of executable)

# `Libraries`

These are files that contain reusable code that can be invoked by another library or an executable. 
Libraries can be binary code. In fact, most of the stuff in /lib is going to be libraries compiled to machine code.

`Static libraries:`

These are the original variety. They consist of an archive file (usually AR format) with a large number of object files inside, one for each function in the library. The object files get linked into the executable that uses them, so an executable that uses just static libraries is essentially 100% independent of any other code. On UNIX systems, they typically have a .a extension. The concept of static libraries doesn't really exist outside of compiled programming languages.

`Dynamic libraries: `

These are the most common type of library used today. A dynamic library is a special object file, typically with a `.so `extension on UNIX (`.dll is the standard on Windows`), that gets loaded at run time by executables that use it. Most of what you'll find in `/lib` on production systems is dynamic libraries.

`Modules`

it's possible for a file to be both a module and an executable (see `http.server` in the Python standard library for an example).