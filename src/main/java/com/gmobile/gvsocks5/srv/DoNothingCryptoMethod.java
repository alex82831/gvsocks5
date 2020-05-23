package com.gmobile.gvsocks5.srv;

import io.vertx.core.buffer.Buffer;

public class DoNothingCryptoMethod implements CryptoMethod {
    @Override
    public Buffer encode(Buffer source) {
        return source;
    }

    @Override
    public Buffer decode(Buffer source) {
        return source;
    }
}
