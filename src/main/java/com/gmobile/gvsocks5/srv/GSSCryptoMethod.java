package com.gmobile.gvsocks5.srv;

import io.vertx.core.buffer.Buffer;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.MessageProp;

@RequiredArgsConstructor
public class GSSCryptoMethod implements CryptoMethod {

    @NonNull
    private final GSSContext gssContext;
    @NonNull
    private final MessageProp prop;

    @Override
    @SneakyThrows
    public Buffer encode(Buffer source) {
        byte [] warpData = gssContext.wrap(source.getBytes(), 0, source.length(), prop);
        byte [] reply = getGSSReply((byte)0x03, warpData);
        return Buffer.buffer(reply);
    }

    @Override
    @SneakyThrows
    public Buffer decode(Buffer source) {
        byte [] bytes = source.getBytes();
        int len = ((bytes[2] & 0xFF) << 8 | (bytes[3] & 0xFF));
        byte [] data = gssContext.unwrap(bytes, 4, len, prop);
        return Buffer.buffer(data);
    }

    public static byte [] getGSSReply(byte mtyp, byte [] token) {
        byte[] reply = new byte[4 + token.length];
        reply[0] = 0x01;
        reply[1] = mtyp;
        System.arraycopy(
                Buffer.buffer(2).setShort(0, (short) token.length).getBytes(), 0,
                reply, 2, 2);
        System.arraycopy(token, token.length, reply, 4, token.length);
        return reply;
    }
}
