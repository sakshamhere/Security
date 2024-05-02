# What is websocket connection
So in general in HTTP or HTTPS the request is sent and response is recieved and then connection is closed

then again same repeats, so this is unidirectional

Now in Web sockets communication is bidirectional so sender and reciever both can send data to each other

So how do they achieve it - simple, they dont close the connection which they open first time, when one of them decides to terminate then connection is terminated from both the ends


websockets urls look like

            ws://www.google.com
            wss://www.google.com

# where websockets can be used

- Chat applications use them heavily

- Gaming applications

- Realtime applications


Some real examples

www.gdax.com
