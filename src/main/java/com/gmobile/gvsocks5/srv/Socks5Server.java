package com.gmobile.gvsocks5.srv;

import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.datagram.DatagramPacket;
import io.vertx.core.datagram.DatagramSocket;
import io.vertx.core.dns.DnsClient;
import io.vertx.core.dns.DnsClientOptions;
import io.vertx.core.impl.Arguments;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import io.vertx.core.net.*;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.codec.digest.HmacUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.RandomUtils;
import org.apache.commons.lang3.StringUtils;
import org.ietf.jgss.GSSManager;

import java.net.ProxySelector;
import java.nio.charset.StandardCharsets;
import java.util.*;


@RequiredArgsConstructor
public class Socks5Server {

    private static final Logger log = LoggerFactory.getLogger(Socks5Server.class);

    private final static int SOCKS_VERSION_5 = 0x05;

    private final static int IPv4 = 0x01;
    private final static int IPv6 = 0x04;
    private final static int DOMAIN = 0x03;

    private final static Buffer NO_SUPPORTED_METHODS = Buffer.buffer(new byte[]{SOCKS_VERSION_5, (byte) 0xff});

    private static final Buffer AUTH_SUCCESS = Buffer.buffer(new byte[]{1, 0});
    private static final Buffer AUTH_FAILED = Buffer.buffer(new byte[]{1, 1});

    private final static int NO_AUTH_METHOD = 0x00;
    private final static int USERNAME_PASSWORD_METHOD = 0x02;
    private final static int GSSAPI_METHOD = 0x01;
    private final static int CHAP_METHOD = 0x03;

    private static final byte SUCCESS = 0x00;
    private static final byte SOCKS5_SERVER_GENERAL_ERROR = 0x01;
    private static final byte CONNECTION_NOT_ALLOWED = 0x02;
    private static final byte NETWORK_UNREACHABLE = 0x03;
    private static final byte HOST_UNREACHABLE = 0x04;
    private static final byte CONNECTION_REFUSED = 0x05;
    private static final byte TTL_EXPIRED = 0x06;
    private static final byte UNSUPPORTED_CMD = 0x07;
    private static final byte UNSUPPORTED_ADDRESS = 0x08;

    @Getter
    private final Vertx vertx = Vertx.vertx(new VertxOptions());
    @Getter
    private final GSSManager gssManager = GSSManager.getInstance();
    @Setter
    @Getter
    private SocketAddress bindAddress = SocketAddress.inetSocketAddress(1080, "0.0.0.0");
    @Getter
    private String username = "";
    @Getter
    private String password = "";
    @Setter
    @Getter
    private String dnsServer;
    private boolean shouldResolveHost = false;
    @Getter
    private String upstreamSocks5ProxyHost = "0.0.0.0";
    @Getter
    private int upstreamSocks5ProxyPort = -1;
    @Getter
    private String upstreamSocks5ProxyUsername = "";
    @Getter
    private String upstreamSocks5ProxyPassword = "";
    private DnsClient dnsClient;
    private NetClient client;
    private final SocksCommandHandler[] socks5CmdHandlers = {
            this::socks5Undefined,
            this::socks5Connect,
            this::socks5Bind,
            this::socks5UDP
    };

    @Getter
    @Setter
    private String chapSecret = "";

    @Getter
    @Setter
    private ProxyProvider proxyProvider = null;

    @Getter
    private final Map<Integer, Socks5AuthMethod> methods = new HashMap<>();
    @Getter
    private final Set<NetSocket> chapHMACMD5Sockets = new HashSet<>();
    @Getter
    private final Map<NetSocket, String> chapChallenges = new HashMap<>();

    public void enableUsernamePasswordMethod(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public void setSocksChain(String upstreamHost, int upstreamPort) {
        if (upstreamHost != null && !upstreamHost.isEmpty()) upstreamSocks5ProxyHost = upstreamHost;
        if (upstreamPort > 0) upstreamSocks5ProxyPort = upstreamPort;
    }

    public void setSocksChain(String upstreamHost, int upstreamPort, String username, String password) {
        setSocksChain(upstreamHost, upstreamPort);
        if (username != null && !username.isEmpty()) upstreamSocks5ProxyUsername = username;
        if (password != null && !password.isEmpty()) upstreamSocks5ProxyPassword = password;
    }

    private void addMethodIfAllNotEmpty(int method, Socks5AuthMethod authFunction, String ... parameters) {
        for(String parameter : parameters) {
            if(StringUtils.isEmpty(parameter)) return;
        }
        methods.put(method, authFunction);
    }

    private void initAuthMethods() {
        addMethodIfAllNotEmpty(USERNAME_PASSWORD_METHOD, this::usernamePasswordAuth, username, password);
        addMethodIfAllNotEmpty(CHAP_METHOD, this::chapMethod, chapSecret);
        if(methods.isEmpty()) methods.put(NO_AUTH_METHOD, this::noAuth);
    }

    private void initTcpClient() {
        NetClientOptions options = new NetClientOptions();
        if (!upstreamSocks5ProxyHost.isEmpty() && upstreamSocks5ProxyPort > 0) {
            log.info("Socks5 Chain Mode");
            ProxyOptions proxyOptions = new ProxyOptions();
            proxyOptions.setHost(upstreamSocks5ProxyHost).setPort(upstreamSocks5ProxyPort).setType(ProxyType.SOCKS5);
            if (!upstreamSocks5ProxyUsername.isEmpty() && !upstreamSocks5ProxyPassword.isEmpty())
                proxyOptions.setUsername(upstreamSocks5ProxyUsername).setPassword(upstreamSocks5ProxyPassword);
            options.setProxyOptions(proxyOptions);
        }
        client = vertx.createNetClient(options);
    }

    private void initDNSClient() {
        if (!dnsServer.equals("0.0.0.0")) {
            DnsClientOptions options = new DnsClientOptions();
            options.setHost(dnsServer);
            dnsClient = vertx.createDnsClient(options);
            shouldResolveHost = true;
        }
    }

    private void initTCPServer() {
        NetServerOptions options = new NetServerOptions();
        options.setPort(bindAddress.port());
        int num = Runtime.getRuntime().availableProcessors();
        for (int i = 0; i < num; i++) {
            NetServer server = vertx.createNetServer(options);
            server.connectHandler(this::newConnection);
            server.listen(bindAddress);
        }
        log.info("Listening on address: " + bindAddress);
    }

    public void start() {
        initAuthMethods();
        initTcpClient();
        initDNSClient();
        initTCPServer();
    }

    private void newConnection(NetSocket socket) {
        log.info("New connection from " + socket.remoteAddress());
        socket.handler(buffer -> socks5Connection(socket, buffer.getBytes()));
    }

    private int convertByteAsUnsigned(byte b) {
        return b & 0xFF;
    }

    private byte[] getReplyBytes(byte result, SocketAddress address, CryptoMethod method) {
        byte atyp = getATYP(address.host());
        int len;
        if (atyp == IPv4) len = 4;
        else if (atyp == IPv6) len = 16;
        else len = 1 + address.host().length();
        Arguments.require((result <= 0x08), "Unsupported result: " + result);
        len += 6;
        byte[] reply = new byte[len];
        reply[0] = SOCKS_VERSION_5;
        reply[1] = result;
        reply[3] = atyp;
        writeHost(reply, address.host(), atyp);
        writePort(reply, address.port());
        return method.encode(Buffer.buffer(reply)).getBytes();
    }

    private void sendSuccess(NetSocket socket, SocketAddress address, CryptoMethod method) {
        byte[] reply = getReplyBytes(SUCCESS, address, method);
        socket.write(Buffer.buffer(reply));
    }

    private byte getATYP(String host) {
        byte atyp;
        if (host.contains(".")) atyp = IPv4;
        else if (host.contains(":")) atyp = IPv6;
        else atyp = DOMAIN;
        return atyp;
    }

    private void socks5Connection(NetSocket socket, byte[] bytes) {
        int countOfMethods = bytes[1];
        if (bytes.length != 2 + countOfMethods) {
            socket.close();
        } else {
            boolean supported = false;
            for (int i = 2; i < bytes.length; i++) {
                if (methods.containsKey((int) bytes[i])) {
                    Socks5AuthMethod method = methods.get((int) bytes[i]);
                    Buffer reply = Buffer.buffer(new byte[]{SOCKS_VERSION_5, bytes[i]});
                    socket.write(reply, ar -> {
                        if (!ar.succeeded()) {
                            socket.close();
                            log.debug(ar.cause().getMessage(), ar.cause());
                        }
                    });
                    method.onAuth(socket, cryptoMethod -> socket.handler(buffer -> socks5Handler(socket, buffer, cryptoMethod)), () -> {
                        socket.close();
                        log.info("AUTH failed");
                    });
                    supported = true;
                }
            }
            if (!supported) {
                log.info("No supported auth methods");
                socket.write(NO_SUPPORTED_METHODS, ar -> {
                    if (!ar.succeeded()) log.debug(ar.cause().getMessage(), ar.cause());
                    socket.close();
                });
            }
        }
    }

    private void noAuth(NetSocket socket, AuthSuccessCallback successCallback, Runnable failedCallback) {
        Objects.requireNonNull(successCallback);
        successCallback.onAuthSuccess(new DoNothingCryptoMethod());
    }

    private void usernamePasswordAuth(NetSocket socket, AuthSuccessCallback successCallback, Runnable failedCallback) {
        Objects.requireNonNull(successCallback);
        Objects.requireNonNull(failedCallback);
        socket.handler(buf -> {
            Buffer authReply = Buffer.buffer(new byte[]{1, (byte) username.length()});
            authReply.appendString(username);
            authReply.appendByte((byte) password.length());
            authReply.appendString(password);
            if (!buf.equals(authReply)) {
                socket.handler(null);
                socket.write(AUTH_FAILED, ar -> {
                    if (!ar.succeeded()) log.info(ar.cause().getMessage(), ar.cause());
                });
                failedCallback.run();
            } else {
                socket.write(AUTH_SUCCESS, ar -> {
                    if (!ar.succeeded()) log.info(ar.cause().getMessage(), ar.cause());
                });
                successCallback.onAuthSuccess(new DoNothingCryptoMethod());
            }
        });
    }

    private void chapMethod(NetSocket socket, AuthSuccessCallback successCallback, Runnable failedCallback) {
        final int CHAP_STATUS = 0;
        final int CHAP_TEXT_MESSAGE = 0x01;
        final int CHAP_USER_IDENTITY = 0x02;
        final int CHAP_CHALLENGE = 0x03;
        final int CHAP_RESPONSE = 0x04;
        final int CHAP_CHARSET = 0x05;
        final int CHAP_IDENTIFIER = 0x10;
        final int CHAP_ALGORITHMS = 0x11;
        final int PHRASE_1 = 1;
        final int PHRASE_2 = 2;
        final int PHRASE_3 = 3;
        final int PHRASE_4 = 4;
        final int PHRASE_KNOWNN = 0xFF;
        final byte MD5 = 0x05;
        final byte HMAC_MD5 = (byte)0x85;
        Objects.requireNonNull(successCallback);
        Objects.requireNonNull(failedCallback);
        socket.handler(buffer -> {
            int phrase = PHRASE_KNOWNN;
            String userIdentifier = null;
            String response = null;
            String clientChallenge= null;
            byte [] bytes = buffer.getBytes();
            if(bytes[0] == 0x01) {
                int navas = bytes[1];
                int pos = 2;
                boolean clientMD5Support = false;
                for(int i = 0; i < navas; i++) {
                    int type = bytes[pos];
                    int len = bytes[pos + 1];
                    switch (type) {
                        case CHAP_ALGORITHMS: {
                            phrase = PHRASE_1;
                            pos += 2;
                            int maxpos = pos + len;
                            for (; pos < maxpos; pos++) {
                                if (bytes[pos] == HMAC_MD5) chapHMACMD5Sockets.add(socket);
                                else if (bytes[pos] == MD5) clientMD5Support = true;
                            }
                            pos++;
                            break;
                        }
                        case CHAP_TEXT_MESSAGE: {
                            StringBuilder strBuilder = new StringBuilder();
                            pos += 2;
                            int maxpos = pos + len;
                            for (; pos < maxpos; pos++) strBuilder.append(bytes[pos]);
                            pos++;
                            log.info("CHAP: Client send message: " + strBuilder.toString());
                            break;
                        }
                        case CHAP_CHARSET:{
                            log.info("CHAP: Does NOT support CHARSET message for now");
                            pos += (3 + len);
                            break;
                        }
                        case CHAP_USER_IDENTITY:{
                            phrase = PHRASE_2;
                            StringBuilder strBuilder = new StringBuilder();
                            pos += 2;
                            int maxpos = pos + len;
                            for (; pos < maxpos; pos++) strBuilder.append(bytes[pos]);
                            pos++;
                            userIdentifier = strBuilder.toString();
                            break;
                        }
                        case CHAP_RESPONSE:{
                            phrase = PHRASE_2;
                            StringBuilder strBuilder = new StringBuilder();
                            pos += 2;
                            int maxpos = pos + len;
                            for (; pos < maxpos; pos++) strBuilder.append(bytes[pos]);
                            pos++;
                            response = strBuilder.toString();
                            break;
                        }
                        case CHAP_CHALLENGE:{
                            StringBuilder strBuilder = new StringBuilder();
                            pos += 2;
                            int maxpos = pos + len;
                            for (; pos < maxpos; pos++) strBuilder.append(bytes[pos]);
                            pos++;
                            clientChallenge = strBuilder.toString();
                            break;
                        }
                        case CHAP_STATUS:{
                            if(bytes[pos + 3] == 0) {
                                phrase = PHRASE_3;
                            } else {
                                phrase = PHRASE_4;
                            }
                            pos += (3 + len);
                            break;
                        }
                        default: {
                            log.info("CHAP: Unsupported socks5 CHAP type: " + type);
                            pos += (3 + len);
                            break;
                        }
                    }
                    if(phrase == PHRASE_3 || phrase == PHRASE_4) break;
                }
                switch(phrase) {
                    case PHRASE_1: {
                        byte[] reply;
                        if (!chapHMACMD5Sockets.contains(socket) && !clientMD5Support) {
                            reply = new byte[]{0x01, 0x01, (byte) CHAP_STATUS, 0x01, (byte) 0xFF};
                            socket.write(Buffer.buffer(reply));
                        } else {
                            reply = new byte[]{0x01, 0x01, (byte) CHAP_ALGORITHMS, 0x01, chapHMACMD5Sockets.contains(socket) ? HMAC_MD5 : MD5};
                            socket.write(Buffer.buffer(reply));
                            String challenge = RandomStringUtils.random(16, true, true);
                            chapChallenges.put(socket, challenge);
                            byte[] reply2 = new byte[4 + challenge.length()];
                            reply2[0] = 0x01;
                            reply2[1] = 0x01;
                            reply2[2] = (byte) CHAP_CHALLENGE;
                            reply2[3] = (byte) challenge.length();
                            byte [] data = challenge.getBytes();
                            System.arraycopy(data, 0, reply2, 4, data.length);
                            socket.write(Buffer.buffer(reply2));
                        }
                        break;
                    }
                    case PHRASE_2: {
                        if (userIdentifier == null || response == null) {
                            log.info("CHAP: Missing USER_IDENTITY or RESPONSE packet");
                            chapHMACMD5Sockets.remove(socket);
                            chapChallenges.remove(socket);
                            failedCallback.run();
                        } else {
                            if (chapChallenges.containsKey(socket)) {
                                String challenge = chapChallenges.get(socket);
                                String computedResponse;
                                if (chapHMACMD5Sockets.contains(socket)) {
                                    computedResponse = HmacUtils.hmacMd5Hex(chapSecret, userIdentifier + "|" + chapSecret + "|" + challenge);
                                } else {
                                    computedResponse = DigestUtils.md5Hex(userIdentifier + "|" + chapSecret + "|" + challenge);
                                }
                                if (computedResponse.equals(response)) {
                                    byte[] reply = new byte[]{0x01, 0x01, (byte) CHAP_STATUS, 0x01, 0};
                                    if (clientChallenge != null) {
                                        String serverResponse;
                                        if (chapHMACMD5Sockets.contains(socket)) {
                                            serverResponse = HmacUtils.hmacMd5Hex(chapSecret, userIdentifier + "|" + chapSecret + "|" + clientChallenge);
                                        } else {
                                            serverResponse = DigestUtils.md5Hex(userIdentifier + "|" + chapSecret + "|" + clientChallenge);
                                        }
                                        byte[] reply2 = new byte[reply.length + 2 + serverResponse.length()];
                                        System.arraycopy(reply, 0, reply2, 0, reply.length);
                                        reply2[1] = 0x02;
                                        reply2[5] = CHAP_RESPONSE;
                                        reply2[6] = (byte)serverResponse.length();
                                        byte [] data = serverResponse.getBytes();
                                        System.arraycopy(data, 0, reply2, 7, data.length);
                                        socket.write(Buffer.buffer(reply2));
                                    } else {
                                        chapHMACMD5Sockets.remove(socket);
                                        chapChallenges.remove(socket);
                                        socket.write(Buffer.buffer(reply));
                                        successCallback.onAuthSuccess(new DoNothingCryptoMethod());
                                    }
                                } else {
                                    byte[] reply = new byte[]{0x01, 0x01, (byte) CHAP_STATUS, 0x01, (byte) 0xFF};
                                    socket.write(Buffer.buffer(reply));
                                    failedCallback.run();
                                }
                            } else {
                                log.info("CHAP: Did not send CHALLENGE but received USER_IDENTITY and RESPONSE. Is someone trying to attack your server?");
                            }
                        }
                        break;
                    }
                    case PHRASE_3:{
                        chapHMACMD5Sockets.remove(socket);
                        chapChallenges.remove(socket);
                        successCallback.onAuthSuccess(new DoNothingCryptoMethod());
                        break;
                    }
                    case PHRASE_4:{
                        chapHMACMD5Sockets.remove(socket);
                        chapChallenges.remove(socket);
                        failedCallback.run();
                        break;
                    }
                    case PHRASE_KNOWNN:
                        log.info("CHAP: Missing or unsupported socks5 CHAP packet type OR internal socks5 server error");
                        chapHMACMD5Sockets.remove(socket);
                        chapChallenges.remove(socket);
                        failedCallback.run();
                        break;
                }
            } else {
                socket.close();
                log.info("CHAP: Unsupported socks5 CHAP version: " + bytes[0]);
                failedCallback.run();
            }
        });
    }

//    private void gssAPIMethod(NetSocket socket, AuthSuccessCallback successCallback, Runnable failedCallback) {
//        Objects.requireNonNull(successCallback);
//        Objects.requireNonNull(failedCallback);
//        if (gssContext == null) failedCallback.run();
//        else {
//            socket.fetch(4);
//            socket.handler(buffer -> {
//                byte[] bytes = buffer.getBytes();
//                if (bytes[0] != 0x01 || bytes[1] != 0x01) {
//                    failedCallback.run();
//                } else {
//                    int len = ((bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF));
//                    socket.fetch(len);
//                    socket.handler(clientTokenBuf -> {
//                        byte[] token;
//                        try {
//                            token = gssContext.acceptSecContext(clientTokenBuf.getBytes(), 0, len);
//                        } catch (GSSException e) {
//                            log.info(e.getMessage(), e);
//                            socket.write(NO_SUPPORTED_METHODS);
//                            return;
//                        }
//                        byte[] reply = getGSSReply((byte)0x01, token);
//                        socket.write(Buffer.buffer(reply));
//                        if (!gssContext.isEstablished()) {
//                            gssAPIMethod(socket, successCallback, failedCallback);
//                        } else {
//                            gssProtectionLevelNegotiation(socket, successCallback, failedCallback);
//                        }
//                    });
//                }
//            });
//        }
//    }
//
//    private void gssProtectionLevelNegotiation(NetSocket socket, AuthSuccessCallback successCallback, Runnable failedCallback) {
//        socket.handler(buffer -> {
//            byte [] packet = buffer.getBytes();
//            if(packet[0] != 0x01 || packet[1] != 0x01) {
//                failedCallback.run();
//            } else {
//                int requiredLevel = packet[4];
//                int serverLevel = 2;
//                if (requiredLevel == 1) serverLevel = 1;
//                packet[4] = (byte) serverLevel;
//                socket.write(Buffer.buffer(packet));
//                MessageProp prop = new MessageProp(serverLevel == 2);
//                successCallback.onAuthSuccess(new GSSCryptoMethod(gssContext, prop));
//            }
//        });
//    }

    private void socks5Handler(NetSocket socket, Buffer buffer, CryptoMethod cryptoMethod) {
        byte[] bytes = cryptoMethod.decode(buffer).getBytes();
        if (bytes.length > 1 && bytes[1] < socks5CmdHandlers.length) {
            socks5CmdHandlers[bytes[1]].onCommand(socket, bytes, cryptoMethod);
        } else {
            sendError(socket, UNSUPPORTED_CMD, cryptoMethod);
        }
    }

    private void sendError(NetSocket socket, byte error, CryptoMethod method) {
        socket.handler(null);
        byte[] reply = getReplyBytes(error, bindAddress, method);
        socket.write(Buffer.buffer(reply), ar -> {
            if (!ar.succeeded()) log.debug(ar.cause().getMessage(), ar.cause());
            socket.close();
        });
    }

    private void socks5Undefined(NetSocket socket, byte[] bytes, CryptoMethod method) {
        sendError(socket, UNSUPPORTED_CMD, method);
    }

    private void socks5Connect(NetSocket socket, byte[] bytes, CryptoMethod method) {
        lookupSocketAddress(bytes, bytes[3], address -> socks5Connect(socket, address, method), () -> sendError(socket, HOST_UNREACHABLE, method));
    }

    private void startTrafficForwarding(NetSocket socketToClient, NetSocket socketToRemote, CryptoMethod method) {
        CryptoPump p1 = new CryptoPump(socketToRemote, socketToClient, null, method);
        CryptoPump p2 = new CryptoPump(socketToClient, socketToRemote, method, null);
        socketToRemote.closeHandler(v -> {
            socketToClient.closeHandler(null);
            socketToClient.close();
            p1.stop();
            p2.stop();
        });
        socketToClient.closeHandler(v -> {
            socketToRemote.closeHandler(null);
            socketToRemote.close();
            p1.stop();
            p2.stop();
        });
        p1.start();
        p2.start();
    }

    private void sendSuccessAndBuildTrafficForwarding(NetSocket socketToClient, NetSocket socketToRemote, CryptoMethod method) {
        byte[] reply = getReplyBytes(SUCCESS, SocketAddress.inetSocketAddress(socketToRemote.localAddress().port(), bindAddress.host()), method);
        socketToClient.write(Buffer.buffer(reply), ar -> {
            if (ar.succeeded()) {
                startTrafficForwarding(socketToClient, socketToRemote, method);
            } else {
                socketToRemote.close();
                sendError(socketToClient, CONNECTION_REFUSED, method);
                log.debug(ar.cause().getMessage(), ar.cause());
            }
        });
    }

    private void socks5Connect(NetSocket socket, SocketAddress address, CryptoMethod method) {
        log.info("SOCKS5 - CONNECT");
        if (address.port() == 0) {
            sendError(socket, UNSUPPORTED_ADDRESS, method);
        } else {
            log.info("Target Address: " + address);
            if(proxyProvider != null) {
                proxyProvider.onCustomProxy(socket.remoteAddress(), address, socketToRemote -> sendSuccessAndBuildTrafficForwarding(socket, socketToRemote, method));
            } else {
                client.connect(address, ar -> {
                    if (ar.succeeded()) {
                        NetSocket socketToRemote = ar.result();
                        sendSuccessAndBuildTrafficForwarding(socket, socketToRemote, method);
                    } else {
                        log.debug(ar.cause().getMessage(), ar.cause());
                        sendError(socket, NETWORK_UNREACHABLE, method);
                    }
                });
            }
        }
    }

    private int getPort(byte b1, byte b2) {
        return ((b1 & 0xFF) << 8 | (b2 & 0xFF));
    }

    private byte[] getPortBytes(short port) {
        Buffer buffer = Buffer.buffer(2);
        return buffer.setShort(0, port).getBytes();
    }

    private void lookupSocketAddress(byte[] bytes, byte atyp, SocketAddressCallback callback, Runnable dnsLookupFailCallback) {
        Arguments.require(callback != null, "Missing socket address callback");
        SocketAddress address;
        switch (atyp) {
            case IPv4: {
                String host = convertByteAsUnsigned(bytes[4]) + "." + convertByteAsUnsigned(bytes[5]) + "." + convertByteAsUnsigned(bytes[6]) + "." + convertByteAsUnsigned(bytes[7]);
                address = SocketAddress.inetSocketAddress(getPort(bytes[8], bytes[9]), host);
            }
            break;
            case DOMAIN: {
                StringBuilder builder = new StringBuilder();
                int i = 5;
                int len = bytes[4];
                for (; i < len + 5; i++) builder.append((char) bytes[i]);
                String hostName = builder.toString();
                int actualPort = getPort(bytes[i], bytes[i + 1]);
                if (shouldResolveHost) {
                    dnsClient.resolveA(hostName, ar -> {
                        if (ar.succeeded()) {
                            List<String> ips = ar.result();
                            if (ips.size() == 0) {
                                if (dnsLookupFailCallback != null) dnsLookupFailCallback.run();
                            } else {
                                String ip = ips.get(RandomUtils.nextInt(0, ips.size()));
                                log.info("Lookup DNS Record for hostname: " + hostName + " Result: " + ip);
                                callback.onAddress(SocketAddress.inetSocketAddress(actualPort, ip));
                            }
                        } else {
                            log.debug(ar.cause().getMessage(), ar.cause());
                            if (dnsLookupFailCallback != null) dnsLookupFailCallback.run();
                        }
                    });
                    return;
                }
                address = SocketAddress.inetSocketAddress(actualPort, hostName);
            }
            break;
            case IPv6: {
                StringBuilder builder = new StringBuilder();
                for (int i = 4; i < 20; i++) {
                    builder.append(Hex.encodeHexString(new byte[]{bytes[i]}));
                    if (i % 2 != 0 && i != 19) builder.append(":");
                }
                address = SocketAddress.inetSocketAddress(getPort(bytes[20], bytes[21]), builder.toString());
            }
            break;
            default: {
                Arguments.require(true, "ERROR: Cannot get target address");
                address = SocketAddress.inetSocketAddress(0, "0.0.0.0");
            }
            break;
        }
        callback.onAddress(address);
    }

    private void socks5Bind(NetSocket socket, byte[] bytes, CryptoMethod method) {
        lookupSocketAddress(bytes, bytes[3], address -> socks5Bind(socket, address, method), () -> sendError(socket, HOST_UNREACHABLE, method));
    }

    private void writePort(byte[] bytes, int port) {
        byte[] portBytes = getPortBytes((short) port);
        System.arraycopy(portBytes, 0, bytes, bytes.length - portBytes.length, portBytes.length);
    }

    private byte[] getHostBytes(String host, int type) throws DecoderException {
        switch (type) {
            case IPv4: {
                byte[] bytes = new byte[4];
                String[] parts = host.split("\\.");
                for (int i = 0; i < bytes.length; i++) bytes[i] = Byte.parseByte(parts[i]);
                return bytes;
            }
            case IPv6: {
                byte[] bytes = new byte[16];
                String[] parts = host.split(":");
                for (int p = 0, i = 0; p < parts.length; p++, i += 2) {
                    bytes[i] = Hex.decodeHex(parts[0].substring(0, 1))[0];
                    bytes[i + 1] = Hex.decodeHex(parts[1].substring(2, 3))[0];
                }
                return bytes;
            }
            case DOMAIN: {
                byte[] chars = host.getBytes(StandardCharsets.UTF_8);
                byte[] bytes = new byte[1 + chars.length];
                bytes[0] = (byte) chars.length;
                System.arraycopy(chars, 0, bytes, 1, chars.length);
                return bytes;
            }
            default:
                Arguments.require(true, "Unsupported host type");
                return "".getBytes();
        }
    }

    private void writeHost(byte[] bytes, String host, int type) {
        try {
            byte[] hostBytes = getHostBytes(host, type);
            switch (type) {
                case IPv4:
                case IPv6:
                case DOMAIN:
                    System.arraycopy(bytes, 4, hostBytes, 0, hostBytes.length);
                    break;
                default:
                    Arguments.require(true, "Unsupported ATYP");
                    break;
            }
        } catch (DecoderException e) {
            log.debug(e.getMessage(), e);
            Arguments.require(true, e.getMessage());
        }
    }

    private void socks5Bind(NetSocket socket, SocketAddress address, CryptoMethod method) {
        log.info("SOCKS5 - BIND");
        if (address.port() == 0) {
            sendError(socket, SOCKS5_SERVER_GENERAL_ERROR, method);
        } else {
            NetServer server = vertx.createNetServer();
            server.listen(0, bindAddress.host(), ar -> {
                if (ar.succeeded()) {
                    server.connectHandler(socketFromAppServer -> {
                        sendSuccess(socket, socketFromAppServer.remoteAddress(), method);
                        startTrafficForwarding(socket, socketFromAppServer, method);
                    });
                    sendSuccess(socket, bindAddress, method);
                } else {
                    sendError(socket, SOCKS5_SERVER_GENERAL_ERROR, method);
                    log.debug(ar.cause().getMessage(), ar.cause());
                }
            });
        }
    }

    private void findAvailablePort(FindPortCallback callback) {
        Arguments.require(callback != null, "FindPortCallback is NULL");
        vertx.createNetServer().listen(0, bindAddress.host(), ar -> {
            if (ar.succeeded()) {
                NetServer server = ar.result();
                server.close(ar1 -> {
                    if (ar1.succeeded()) callback.onPort(server.actualPort());
                    else callback.onPort(-1);
                });
            } else {
                callback.onPort(-1);
            }
        });
    }

    private void forwardUDPToTCP(DatagramPacket packet, NetSocket socket, byte type) throws DecoderException {
        byte[] addrBytes = getHostBytes(packet.sender().host(), type);
        byte[] portBytes = getPortBytes((short) packet.sender().port());
        byte[] reply = new byte[4 + addrBytes.length + portBytes.length + packet.data().length()];
        reply[3] = type;
        System.arraycopy(reply, 4, addrBytes, 0, addrBytes.length);
        System.arraycopy(reply, 4 + addrBytes.length, portBytes, 0, portBytes.length);
        System.arraycopy(reply, 4 + addrBytes.length + portBytes.length, packet.data().getBytes(), 0, packet.data().length());
        socket.write(Buffer.buffer(reply));
    }

    private void sendDataToUDP(byte[] packetData, byte type, DatagramSocket udpSocket, Runnable dnsErrorCallback) {
        lookupSocketAddress(packetData, type, address -> {
            int dataPos = 10;
            if (type == IPv6) dataPos = 22;
            else if (type == DOMAIN) dataPos = 7 + address.host().length();
            byte[] sentData = new byte[packetData.length - dataPos];
            System.arraycopy(sentData, 0, packetData, dataPos, sentData.length);
            Buffer buffer = Buffer.buffer(sentData);
            udpSocket.send(buffer, address.port(), address.host(), ar -> {
            });
        }, dnsErrorCallback);
    }

    private void socks5UDP(NetSocket socket, byte[] bytes, CryptoMethod method) {
        log.info("SOCKS5 - UDP");
        byte atyp = bytes[3];
        lookupSocketAddress(bytes, atyp, address -> findAvailablePort(lPort -> {
            if (lPort > 0) {
                sendSuccess(socket, bindAddress, method);
                DatagramSocket udpSocket = vertx.createDatagramSocket();
                udpSocket.listen(lPort, bindAddress.host(), ar -> {
                    if (ar.succeeded()) {
                        udpSocket.handler(packet -> {
                            if (packet.sender().equals(address)) {
                                try {
                                    forwardUDPToTCP(packet, socket, atyp);
                                } catch (DecoderException e) {
                                    log.debug(e.getMessage(), e);
                                    sendError(socket, SOCKS5_SERVER_GENERAL_ERROR, method);
                                    udpSocket.close();
                                }
                            }
                        });
                    }
                });
                socket.handler(buffer -> sendDataToUDP(buffer.getBytes(), atyp, udpSocket, () -> {
                    udpSocket.close();
                    sendError(socket, HOST_UNREACHABLE, method);
                }));
                socket.closeHandler(ar -> udpSocket.close());
            } else {
                sendError(socket, SOCKS5_SERVER_GENERAL_ERROR, method);
            }
        }), () -> sendError(socket, HOST_UNREACHABLE, method));
    }

    @FunctionalInterface
    private interface SocksCommandHandler {
        void onCommand(NetSocket socket, byte[] bytes, CryptoMethod method);
    }

    @FunctionalInterface
    private interface SocketAddressCallback {
        void onAddress(SocketAddress address);
    }

    @FunctionalInterface
    private interface FindPortCallback {
        void onPort(int port);
    }

    @FunctionalInterface
    private interface AuthSuccessCallback {
        void onAuthSuccess(CryptoMethod cryptoMethod);
    }

    @FunctionalInterface
    private interface Socks5AuthMethod {
        void onAuth(NetSocket socket, AuthSuccessCallback successCallback, Runnable failedCallback);
    }

    @FunctionalInterface
    public interface Socks5ConnectHandler {
        void onConnect(NetSocket socket);
    }

    @FunctionalInterface
    public interface ProxyProvider {
        void onCustomProxy(SocketAddress remoteAddrrss, SocketAddress target, Socks5ConnectHandler connectedHandler);
    }
}