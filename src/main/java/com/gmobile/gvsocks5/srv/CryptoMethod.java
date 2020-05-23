package com.gmobile.gvsocks5.srv;

import io.vertx.core.buffer.Buffer;

public interface CryptoMethod {
    Buffer encode(Buffer source);
    Buffer decode(Buffer source);
}