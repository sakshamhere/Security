
# Input Validation

### Allowlist/whitelist approach

It is important to note that a common mistake is to use deny lists for validation. For example an application will prevent symbols that are known to cause trouble. The weakness of this approach is that some symbols may be overlooked.

![alt text](image.png)


### Defined format strings

Always keep format strings fixed in the code, never from user input.

```
// ❌ Dangerous
printf(user_input);

// ✅ Safe
printf("%s", user_input);
```
```
// ❌ Dangerous: user controls the format string
String userInput = "%x %x %x";  
System.out.printf(userInput);

// ✅ Safe: keep format fixed
System.out.printf("%s", userInput);
```

### Avoiding unexpected specifiers (%n etc)

Avoid %n or unexpected format specifiers from user data, Strip out unexpected % symbols from user strings
```
// ❌ Dangerous if user provides "%n"
String userInput = "%n%n%n";
System.out.printf(userInput); // tries to write newlines 
```


# Input Utilization

### Use of Parameterized Statements

Parameterized Statements are used to prevent both SQL Injection and Command Injection vulnerabilities which are listed at the top of OWASP Top 10 Application Security Risks and MITRE Top 25 Most Dangerous Software Errors.

![alt text](image-1.png)

# Memory Utilization

Memory related vulnerabilities are very dangerous. To prevent such vulnerabilities programmers can employ safe memory management practices such as:

- Functions that control the amount of data read into the memory
- Input and input size validation
- Using constants for buffer sizes
- Paying attention to comparison operators while reading into the memory
- Avoiding input in a format string

### Defined input size

Buffer overflows (e.g., writing beyond allocated memory) - Always limit the maximum size, to prevent memory related issues

![alt text](image-2.png)

C example
```
#include <stdio.h>

int main(void) {
    const size_t MAX_LEN = 50;
    char buf[MAX_LEN];

    // ❌ Unsafe: no limit, may overflow
    // scanf("%s", buf);

    // ✅ Safe: limit input size to leave room for '\0'
    scanf("%49s", buf);  

    printf("You entered: %s\n", buf);
    return 0;
}

```
Java example - (Java doesn’t have raw buffer overflows, but incorrect size checks can still lead to memory issues.)
```
String userInput = scanner.nextLine();

// ❌ Unsafe: no length check, could blow up memory
System.out.printf("%s", userInput);

// ✅ Safe: restrict size
if (userInput.length() > 1000) {
    throw new IllegalArgumentException("Input too long!");
}
System.out.printf("%s", userInput);
```
```
// ✅ Safe input reading
Scanner scanner = new Scanner(System.in);
String userInput = scanner.nextLine();
```

### Correct use of Comparison Operator

This matters a lot when preventing overflows (in C) or memory exhaustion (in Java).
When reading into a buffer (C, C++) or allocating memory for input (Java, C#):

- If you use <= instead of <, or forget to subtract one for the null terminator in C, you can allow one extra byte → buffer overflow.
- If you forget to check the upper bound at all, input might overwrite memory or eat all available memory.
- Off-by-one mistakes in loops (i <= size instead of i < size) often cause out-of-bounds reads/writes.

![alt text](image-3.png)

# Unauthorized Access

### Direct object reference

# Cryptographic Failures

### Insecure password storage

Using one-way salted hashes with multiple iterations to store passwords

Why bad: no salt, single fast hash → attackers can precompute and brute force quickly.

Non-secure (bad)
```
# BAD: unsalted, single-round hash (vulnerable to rainbow tables and fast brute force)
import hashlib

def store_password_bad(password):
    digest = hashlib.sha256(password.encode('utf-8')).hexdigest()   # no salt, one round
    # store digest in DB
    return digest
```

Secure (good) — Python (PBKDF2)
```
# GOOD: PBKDF2 with per-user salt and many iterations; store salt, iterations, algo, and derived key
import os, hashlib, base64

def hash_password(password: str, iterations: int = 200_000) -> str:
    salt = os.urandom(16)  # 128-bit salt
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=32)
    # store an encoding that includes algorithm, iterations, salt and derived key
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"

def verify_password(stored: str, candidate: str) -> bool:
    algo, iters_s, salt_b64, dk_b64 = stored.split('$')
    iterations = int(iters_s)
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(dk_b64)
    derived = hashlib.pbkdf2_hmac('sha256', candidate.encode(), salt, iterations, dklen=len(expected))
    # constant-time comparison
    return hashlib.compare_digest(derived, expected)
```

# Logging

### Safe Logging Framework

Prefer logging frameworks (java.util.logging, SLF4J, Log4j2) which separate format strings from data.

```
// ✅ Using SLF4J (safe because {} placeholders aren’t format strings)
logger.info("User input: {}", userInput);
```