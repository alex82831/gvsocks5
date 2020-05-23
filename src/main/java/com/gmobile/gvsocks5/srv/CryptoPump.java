package com.gmobile.gvsocks5.srv;

import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;

public class CryptoPump {

    private final ReadStream<Buffer> readStream;
    private final WriteStream<Buffer> writeStream;
    private final Handler<Buffer> dataHandler;
    private final Handler<Void> drainHandler;
    private int pumped;

    CryptoPump(ReadStream<Buffer> rs, WriteStream<Buffer> ws, CryptoMethod readMethod, CryptoMethod wrtMethod) {
        this.readStream = rs;
        this.writeStream = ws;
        this.drainHandler = (v) -> this.readStream.resume();
        this.dataHandler = (data) -> {
            if(readMethod != null) data = readMethod.decode(data);
            else if(wrtMethod != null) data = wrtMethod.encode(data);
            this.writeStream.write(data);
            this.incPumped();
            if (this.writeStream.writeQueueFull()) {
                this.readStream.pause();
                this.writeStream.drainHandler(this.drainHandler);
            }
        };
    }

    public CryptoPump start() {
        this.readStream.handler(this.dataHandler);
        return this;
    }

    public CryptoPump stop() {
        this.writeStream.drainHandler(null);
        this.readStream.handler(null);
        return this;
    }

    public synchronized int numberPumped() {
        return this.pumped;
    }

    private synchronized void incPumped() {
        ++this.pumped;
    }
}
