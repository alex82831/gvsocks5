package com.gmobile.gvsocks5.srv;

import io.vertx.core.buffer.Buffer;
import io.vertx.core.logging.Logger;
import io.vertx.core.logging.LoggerFactory;
import lombok.Getter;
import lombok.SneakyThrows;
import org.ietf.jgss.*;

public class GSSCryptoMethod implements CryptoMethod {

    private static final Logger log = LoggerFactory.getLogger(GSSCryptoMethod.class);
    @Getter
    private final GSSManager gssManager;
    @Getter
    private GSSContext gssContext;
    @Getter
    private MessageProp prop;

    GSSCryptoMethod(String gssUsername) {
        gssManager = GSSManager.getInstance();
        try {
            GSSName name = gssManager.createName(gssUsername, null);
            Oid krb5Oid = new Oid("1.2.840.113554.1.2.2"); // RFC-1964 defined Oid for Kerberos V5
            GSSCredential gssCredential = gssManager.createCredential(name, GSSContext.DEFAULT_LIFETIME, krb5Oid, GSSCredential.INITIATE_AND_ACCEPT);
            gssContext = gssManager.createContext(gssCredential);
        } catch (GSSException e) {
            e.printStackTrace();
            log.debug(e.getMessage(), e);
            log.info("GSSContext init failed.");
        }
    }

    public static byte[] getGSSReply(byte mtyp, byte[] token) {
        byte[] reply = new byte[4 + token.length];
        reply[0] = 0x01;
        reply[1] = mtyp;
        System.arraycopy(
                Buffer.buffer(2).setShort(0, (short) token.length).getBytes(), 0,
                reply, 2, 2);
        System.arraycopy(token, token.length, reply, 4, token.length);
        return reply;
    }

    @Override
    @SneakyThrows
    public Buffer encode(Buffer source) {
        byte[] warpData = gssContext.wrap(source.getBytes(), 0, source.length(), prop);
        byte[] reply = getGSSReply((byte) 0x03, warpData);
        return Buffer.buffer(reply);
    }

    @Override
    @SneakyThrows
    public Buffer decode(Buffer source) {
        byte[] bytes = source.getBytes();
        int len = ((bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF));
        byte[] data = gssContext.unwrap(bytes, 4, len, prop);
        return Buffer.buffer(data);
    }
}
