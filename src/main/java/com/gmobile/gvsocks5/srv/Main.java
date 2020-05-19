package com.gmobile.gvsocks5.srv;

import com.gmobile.gvsocks5.srv.commons.CommandLineParser;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.impl.Arguments;
import io.vertx.core.net.ProxyOptions;
import io.vertx.core.net.ProxyType;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.client.WebClientOptions;
import lombok.NonNull;

import java.util.Map;
import java.util.concurrent.TimeUnit;

public class Main {

    public static void main(String [] args) throws InterruptedException {
        CommandLineParser parser = new CommandLineParser();
        parser.parse(args);
        runOptions(parser);
        while(true) Thread.sleep(TimeUnit.HOURS.toMillis(1));
    }

    private static void runOptions(CommandLineParser parser) {
        Map<String, String> args = parser.getParseResultAsKeyValuePair();
        String username = getOrDefault(args, "username", "u", "");
        String password = getOrDefault(args, "password", "w", "");
        Socks5Server socks5Server = new Socks5Server();
        if(!username.isEmpty() && !password.isEmpty()) {
            socks5Server.enableUsernamePasswordMethod(username, password);
        }
        socks5Server.setBindAddress(SocketAddress.inetSocketAddress(
                Integer.parseInt(getOrDefault(args, "port", "p", "1080")),
                getOrDefault(args, "bind", "b", "0.0.0.0")));
        String upstreamHost = getOrDefault(args, "upstreamHost", "uh", "");
        int upstreamPort = Integer.parseInt(getOrDefault(args, "upstreamPort", "up", "0"));
        String upstreamUsername = getOrDefault(args, "upstreamUsername", "uu", "");
        String upstreamPassword = getOrDefault(args, "upstreamPassword", "uw", "");
        socks5Server.setSocksChain(upstreamHost, upstreamPort, upstreamUsername, upstreamPassword);
        socks5Server.setDnsServer(getOrDefault(args, "dnsServer", "n", "0.0.0.0"));
        socks5Server.start();
    }

    private static String getOrDefault(Map<String, String> args, String name, String shortName, String defValue) {
        if(args.containsKey(name)) return args.get(name);
        if(args.containsKey(shortName)) return args.get(shortName);
        return defValue;
    }
}