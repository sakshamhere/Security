
So To understand more I did a `Wireshark` analysis for amazon.in,  I started wireshark and simply typed amazon.in on browser tab

More detaild  - http://www.cs.bc.edu/~straubin/crypto2017/demosteps.pdf

# 1. Browser fist sent DNS query, to which it get answers 

DNS	117	Standard query response 0x503d A amazon.in A `54.239.33.92` A `52.95.116.115` A `52.95.120.67`

# 2. Then TCP Handshake started with `54.239.33.92` (SYN, SYN-ACK, and ACK)

# 3. Then TLS handshake started

TLS 1.2  (Not that it dosent mean amazon uses 1.2, it was changed later to 1.3 for furhter network packets)

# Source        Destination     Protocol    Lenght          Info

192.168.46.128	192.168.46.2	DNS	        69	            Standard query 0x3f48 AAAA amazon.in

192.168.46.2	192.168.46.128	DNS	        117	            Standard query response 0x1e70 A amazon.in A 52.95.116.115 A 54.239.33.92 A 52.95.120.67

192.168.46.128	54.239.33.92	TCP	        74	            32874 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=1048603990 TSecr=0 WS=128

54.239.33.92	192.168.46.128	TCP	        60	            443 → 32874 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0 MSS=1460

192.168.46.128	54.239.33.92	TCP	        54	            32874 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0

192.168.46.128	54.239.33.92	TLSv1.2	    571	            Client Hello

54.239.33.92	192.168.46.128	TLSv1.2	    6179	        Server Hello, Certificate, Certificate Status, Server Key Exchange, Server Hello Done

192.168.46.128	54.239.33.92	TLSv1.2	    180	            Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message

54.239.33.92	192.168.46.128	TLSv1.2	    105	            Change Cipher Spec, Encrypted Handshake Message

192.168.46.128	54.239.33.92	TLSv1.2	    885	            Application Data

54.239.33.92	192.168.46.128	TLSv1.2	    455	            Application Data

**********************************************************************************************************************************************************

# 	192.168.46.128	54.239.33.92	TLSv1.2	571	Client Hello

Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.0 (0x0301)
        Length: 512
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 508
            Version: TLS 1.2 (0x0303)
            `Random`: d6f9a56d8580577f03bfa2793cccb299cda4274902d4014b6805e72527f8afb0
                GMT Unix Time: Apr 15, 2084 20:57:17.000000000 EDT
                Random Bytes: 8580577f03bfa2793cccb299cda4274902d4014b6805e72527f8afb0
            Session ID Length: 32
            Session ID: 3029ce3bc040971619d87af32ffbad4613b7de2729fdfe49b1b69dc2e9e19040
            Cipher Suites Length: 34
            `Cipher Suites` (17 suites)
                Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
                Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
                Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
                Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
                Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
                Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
                Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
                Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
                Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
                Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
            Compression Methods Length: 1
            Compression Methods (1 method)
                Compression Method: null (0)
            Extensions Length: 401
            Extension: server_name (len=14)
                Type: server_name (0)
                Length: 14
                Server Name Indication extension
                    Server Name list length: 12
                    Server Name Type: host_name (0)
                    Server Name length: 9
                    Server Name: amazon.in
            Extension: extended_master_secret (len=0)
                Type: extended_master_secret (23)
                Length: 0
            Extension: `renegotiation_info` (len=1)
                Type: renegotiation_info (65281)
                Length: 1
                Renegotiation Info extension
                    Renegotiation info extension length: 0
            Extension: supported_groups (len=14)
                Type: supported_groups (10)
                Length: 14
                Supported Groups List Length: 12
                Supported Groups (6 groups)
            Extension: ec_point_formats (len=2)
                Type: ec_point_formats (11)
                Length: 2
                EC point formats Length: 1
                Elliptic curves point formats (1)
            Extension: `session_ticket` (len=0)
                Type: session_ticket (35)
                Length: 0
                Data (0 bytes)
            Extension: application_layer_protocol_negotiation (len=14)
                Type: application_layer_protocol_negotiation (16)
                Length: 14
                ALPN Extension Length: 12
                ALPN Protocol
            Extension: status_request (len=5)
                Type: status_request (5)
                Length: 5
                Certificate Status Type: OCSP (1)
                Responder ID list Length: 0
                Request Extensions Length: 0
            Extension: delegated_credentials (len=10)
                Type: delegated_credentials (34)
                Length: 10
                Signature Hash Algorithms Length: 8
                Signature Hash Algorithms (4 algorithms)
                    Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
                    Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
                    Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
                    Signature Algorithm: ecdsa_sha1 (0x0203)
            Extension: key_share (len=107)
                Type: key_share (51)
                Length: 107
                Key Share extension
                    Client Key Share Length: 105
                    Key Share Entry: Group: x25519, Key Exchange length: 32
                        Group: x25519 (29)
                        Key Exchange Length: 32
                        Key Exchange: 859a845b1c5825cc4c59ed478109854123607dba3144834d97565729a9e2c652
                    Key Share Entry: Group: secp256r1, Key Exchange length: 65
                        Group: secp256r1 (23)
                        Key Exchange Length: 65
                        Key Exchange: 0412d81aff44de04be95555d00447812cb7b2d5fcd539a9543f8a8696453ec978434f1e1…
            Extension: `supported_versions` (len=5)
                Type: supported_versions (43)
                Length: 5
                Supported Versions length: 4
                Supported Version: TLS 1.3 (0x0304)
                Supported Version: TLS 1.2 (0x0303)
            Extension: `signature_algorithms` (len=24)
                Type: signature_algorithms (13)
                Length: 24
                Signature Hash Algorithms Length: 22
                Signature Hash Algorithms (11 algorithms)
                    Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
                        Signature Hash Algorithm Hash: SHA256 (4)
                        Signature Hash Algorithm Signature: ECDSA (3)
                    Signature Algorithm: ecdsa_secp384r1_sha384 (0x0503)
                        Signature Hash Algorithm Hash: SHA384 (5)
                        Signature Hash Algorithm Signature: ECDSA (3)
                    Signature Algorithm: ecdsa_secp521r1_sha512 (0x0603)
                        Signature Hash Algorithm Hash: SHA512 (6)
                        Signature Hash Algorithm Signature: ECDSA (3)
                    Signature Algorithm: rsa_pss_rsae_sha256 (0x0804)
                        Signature Hash Algorithm Hash: Unknown (8)
                        Signature Hash Algorithm Signature: SM2 (4)
                    Signature Algorithm: rsa_pss_rsae_sha384 (0x0805)
                        Signature Hash Algorithm Hash: Unknown (8)
                        Signature Hash Algorithm Signature: Unknown (5)
                    Signature Algorithm: rsa_pss_rsae_sha512 (0x0806)
                        Signature Hash Algorithm Hash: Unknown (8)
                        Signature Hash Algorithm Signature: Unknown (6)
                    Signature Algorithm: rsa_pkcs1_sha256 (0x0401)
                        Signature Hash Algorithm Hash: SHA256 (4)
                        Signature Hash Algorithm Signature: RSA (1)
                    Signature Algorithm: rsa_pkcs1_sha384 (0x0501)
                        Signature Hash Algorithm Hash: SHA384 (5)
                        Signature Hash Algorithm Signature: RSA (1)
                    Signature Algorithm: rsa_pkcs1_sha512 (0x0601)
                        Signature Hash Algorithm Hash: SHA512 (6)
                        Signature Hash Algorithm Signature: RSA (1)
                    Signature Algorithm: ecdsa_sha1 (0x0203)
                        Signature Hash Algorithm Hash: SHA1 (2)
                        Signature Hash Algorithm Signature: ECDSA (3)
                    Signature Algorithm: rsa_pkcs1_sha1 (0x0201)
                        Signature Hash Algorithm Hash: SHA1 (2)
                        Signature Hash Algorithm Signature: RSA (1)
            Extension: psk_key_exchange_modes (len=2)
                Type: psk_key_exchange_modes (45)
                Length: 2
                PSK Key Exchange Modes Length: 1
                PSK Key Exchange Mode: PSK with (EC)DHE key establishment (psk_dhe_ke) (1)
            Extension: record_size_limit (len=2)
                Type: record_size_limit (28)
                Length: 2
                Record Size Limit: 16385
            Extension: padding (len=141)
                Type: padding (21)
                Length: 141
                Padding Data: 000000000000000000000000000000000000000000000000000000000000000000000000…
            [JA3 Fullstring: 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,29-23-24-25-256-257,0]
            [JA3: 579ccef312d18482fc42e2b822ca2430]


# 54.239.33.92	192.168.46.128	TLSv1.2	6179	Server Hello, Certificate, Certificate Status, Server Key Exchange, Server Hello Done

Transport Layer Security
    `TLSv1.2 Record Layer: Handshake Protocol: Server Hello`
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 97
        Handshake Protocol: Server Hello
            Handshake Type: Server Hello (2)
            Length: 93
            Version: TLS 1.2 (0x0303)
            `Random`: 81105445b8b215b779d61b700c78d26666ab87317819fc1e482b4a3810f46d0a
                GMT Unix Time: Aug 13, 2038 12:50:13.000000000 EDT
                Random Bytes: b8b215b779d61b700c78d26666ab87317819fc1e482b4a3810f46d0a
            Session ID Length: 32
            Session ID: 7d30cb9f16a121a8189dcbaeb727c313d54bf3209aed959159682fd6f273610c
            `Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)`
            Compression Method: null (0)
            Extensions Length: 21
            Extension: server_name (len=0)
                Type: server_name (0)
                Length: 0
            Extension: renegotiation_info (len=1)
                Type: renegotiation_info (65281)
                Length: 1
                Renegotiation Info extension
                    Renegotiation info extension length: 0
            Extension: ec_point_formats (len=4)
                Type: ec_point_formats (11)
                Length: 4
                EC point formats Length: 3
                Elliptic curves point formats (3)
            Extension: status_request (len=0)
                Type: status_request (5)
                Length: 0
            [JA3S Fullstring: 771,49199,0-65281-11-5]
            [JA3S: 8bbcb0bf0a942234f77bd504ffdd2013]
    `TLSv1.2 Record Layer: Handshake Protocol: Certificate`
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 5187
        Handshake Protocol: Certificate
            Handshake Type: Certificate (11)
            Length: 5183
            Certificates Length: 5180
            Certificates (5180 bytes)
                Certificate Length: 1727
                Certificate: 308206bb308205a3a003020102021001f99d54a0c90d7eb38b6288caa9ceca300d06092a… (id-at-commonName=*.cy.peg.a2z.com)
                Certificate Length: 1122
                Certificate: 3082045e30820346a0030201020213077312380b9d6688a33b1ed9bf9ccda68e0e0f300d… (id-at-commonName=Amazon RSA 2048 M01,id-at-organizationName=Amazon,id-at-countryName=US)
                Certificate Length: 1174
                Certificate: 308204923082037aa0030201020213067f944a2a27cdf3fac2ae2b01f908eeb9c4c6300d… (id-at-commonName=Amazon Root CA 1,id-at-organizationName=Amazon,id-at-countryName=US)
                Certificate Length: 1145
                Certificate: 308204753082035da003020102020900a70e4a4c3482b77f300d06092a864886f70d0101… (id-at-commonName=Starfield Services Root Certificate Authority - G2,id-at-organizationName=Starfield Technologies, Inc.,id-at-localityName=Scottsdale
    TLSv1.2 Record Layer: Handshake Protocol: Certificate Status
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 479
        Handshake Protocol: Certificate Status
            Handshake Type: Certificate Status (22)
            Length: 475
            Certificate Status Type: OCSP (1)
            OCSP Response Length: 471
            OCSP Response
                responseStatus: successful (0)
                responseBytes
    `TLSv1.2 Record Layer: Handshake Protocol: Server Key Exchange`
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 333
        Handshake Protocol: Server Key Exchange
            Handshake Type: Server Key Exchange (12)
            Length: 329
            `EC Diffie-Hellman Server Params`
                Curve Type: named_curve (0x03)
                Named Curve: secp256r1 (0x0017)
                Pubkey Length: 65
                Pubkey: 047f6df449e7049d187f2c1963fcada09ed96804d3070fef20ef3954c1a5d2e54120cbb0…
                `Signature Algorithm: rsa_pkcs1_sha512 (0x0601)`
                    Signature Hash Algorithm Hash: SHA512 (6)
                    Signature Hash Algorithm Signature: RSA (1)
                Signature Length: 256
                Signature: 0416defa5b265f28762f6e5d760803afb77b5334442562130e2749e8900e6ae3a1a72040…
    `TLSv1.2 Record Layer: Handshake Protocol: Server Hello Done`
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 4
        Handshake Protocol: Server Hello Done
            Handshake Type: Server Hello Done (14)
            Length: 0

# 192.168.46.128	54.239.33.92	TLSv1.2	180	Client Key Exchange, Change Cipher Spec, Encrypted Handshake Message

Transport Layer Security
    `TLSv1.2 Record Layer: Handshake Protocol: Client Key Exchange`
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 70
        Handshake Protocol: Client Key Exchange
            Handshake Type: Client Key Exchange (16)
            Length: 66
            `EC Diffie-Hellman Client Params``
                Pubkey Length: 65
                Pubkey: 04b673fed65476ff22906599256264e482c678310a74316395f41e932b63c2d4be17d512…
    `TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec`
        Content Type: Change Cipher Spec (20)
        Version: TLS 1.2 (0x0303)
        Length: 1
        Change Cipher Spec Message
    `TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Message`
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 40
        Handshake Protocol: Encrypted Handshake Message


# 54.239.33.92	192.168.46.128	TLSv1.2	105	Change Cipher Spec, Encrypted Handshake Message

Transport Layer Security
    `TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec`
        Content Type: Change Cipher Spec (20)
        Version: TLS 1.2 (0x0303)
        Length: 1
        Change Cipher Spec Message
    `TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Message`
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 40
        Handshake Protocol: Encrypted Handshake Message

At this point TLS handshake is done now encrypted data will be sent

# 54.239.33.92	192.168.46.128	TLSv1.2	455	Application Data

Transport Layer Security
    TLSv1.2 Record Layer: Application Data Protocol: Hypertext Transfer Protocol
        Content Type: Application Data (23)
        Version: TLS 1.2 (0x0303)
        Length: 396
        Encrypted Application Data: 921c5b792e5700afaaa80e8847fa6a81cde5116ef299f677373ba080311fb99baee84a06…
        [Application Data Protocol: Hypertext Transfer Protocol]
