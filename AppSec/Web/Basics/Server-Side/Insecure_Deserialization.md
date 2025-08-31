
Note  - Be aware that when working with different programming languages, serialization may be referred to as `marshalling (Ruby)` or `pickling (Python)`. These terms are synonymous with `"serialization"` in this context.

# Identifying

#### PHP

The native methods for PHP serialization are` serialize() and unserialize()`. If you have source code access, you should start by looking for` unserialize()` anywhere in the code and investigating further.

#### JAVA

Any class that implements the interface` java.io.Serializable` can be serialized and deserialized. If you have source code access, take note of any code that uses the `readObject()` method, which is used to read and deserialize data from an `InputStream.`