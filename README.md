# gvsocks5
Full-featured SOCKS5 server based on Vertx

This is a full function socks5 server implementation written in 100% pure Java and based on Vertx framework. It supports IPv6 and all socks5 commands CONNECT, BIND and UDP. 
It's fast and very small you can embed it into your project with just 2 lines of code. Requires JDK11 or above. 

Currently, it only supports NO_AUTH method and USERNAME_PASSWORD method. Plan to add more auth methods.

**Run as a standalone application**
```
java -jar gvsocks.jar -p 1080 -username alex -password 123123
``` 
This will initialize a socks5 proxy listening on port 1080 and set username to 'alex' and password to '123123'
Please refer to source code for other useful options to control proxy behavior

**How to start an open socks5 proxy with NO_AUTH method enabled:**
```
Socks5Server socks5Server = new Socks5Server();
socks5Server.start();
```
This will start an open socks5 proxy on port 1080.

**How to start a socks5 proxy with USERNAME_PASSWORD method enabled:**
```
Socks5Server socks5Server = new Socks5Server();
socks5Server.enableUsernamePasswordMethod("alex", "123123");
socks5Server.start();
```
This will initialize a socks5 proxy and set username to 'alex' and password to '123123'

**How to start socks5 proxy with chaining to upstream socks5 proxy:**
```
Socks5Server socks5Server = new Socks5Server();
socks5Server.setSocksChain("upstream.host", 1080);
socks5Server.start();
```
This will initialize a socks5 proxy which will send request to upstream proxy instead of direct connecting. Also, you can use
```
setSocksChain(String upstreamHost, int upstreamPort, String username, String password)
```
to connect to USERNAME_PASSWORD enabled upstream socks5 proxy.

Some clients will send hostname instead of actual IP address to force resolve DNS record on server side. This is very useful if you are behind a firewall or in a DNS polluted env.
We will use default DNS server for that work, and you can use setDnsServer() to use your own.

Please note that all set functions must be called before start()
