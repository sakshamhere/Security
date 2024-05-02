
# https://github.com/ESAPI/esapi-java-legacy

ESAPI also provides a suite of encoding methods

# XXS

HTML encoder such as `org.owasp.esapi.Encoder.encodeForHTML` 

# Log Injection (encoding CR-LF)

For example, using an HTML encoder such as `org.owasp.esapi.Encoder.encodeForHTML` would cleanse CRLF characters (i.e., remediating the flaw) but the log may end up looking more “HTML-esque” and less human-readable, than if for example `org.owasp.encoder.Encode.forJava` was used instead. Note that if the logs are to be viewed as HTML then encoding for HTML would be a much better solution than calling e.g. `org.owasp.encoder.Encode.forJava`. You should always use a cleansing function that does not encode any characters you may want to log to your log files.