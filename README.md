# gvsocks5
Full-featured SOCKS5 server based on Vertx

This is a socks5 server java implementation based on Vertx. It supports IPv6 and all socks5 commands CONNECT, BIND and UDP. 
It's fast and very small you can embed it into your project with just 2 lines of code. 

Currently it only supports NO_AUTH method and USERNAME_PASSWORD method. Plan to add more auth methods.

**How to setup a open socks5 proxy with NO_AUTH method enabled:**
```
Socks5Server socks5Server = new Socks5Server();
socks5Server.start();
```
This will start a open socks5 proxy on port 1080.

**How to setup a socks5 proxy with USERNAME_PASSWORD method enabled:**
```
Socks5Server socks5Server = new Socks5Server();
socks5Server.enableUsernamePasswordMethod("alex", "123123");
socks5Server.start();
```
This will initialize a socks5 proxy with username 'alex' and password '123123'

**How to setup socks5 proxy with chainning to upstream socks5 proxy:**
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
We will use default DNS server for that work but you can use setDnsServer() to use your own.

Please note that all set functions must be called before start()
