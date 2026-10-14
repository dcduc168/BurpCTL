package dev.burpctl.ipc;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Map;

public final class Frames implements AutoCloseable {
    public static final int MAX_PAYLOAD = 262144;
    private final SocketChannel client;
    private final Selector selector;
    private final long deadline;
    public Frames(SocketChannel client) throws IOException { this(client, 30000); }
    public Frames(SocketChannel client, long timeoutMillis) throws IOException {
        deadline = System.nanoTime() + timeoutMillis * 1_000_000;
        this.client = client;
        client.configureBlocking(false);
        selector = Selector.open();
        try { client.register(selector, SelectionKey.OP_READ); }
        catch (IOException | RuntimeException e) { selector.close(); throw e; }
    }
    private void transfer(ByteBuffer bytes, boolean write) throws IOException {
        client.keyFor(selector).interestOps(write ? SelectionKey.OP_WRITE : SelectionKey.OP_READ);
        while (bytes.hasRemaining()) {
            if (System.nanoTime() >= deadline) throw new java.net.SocketTimeoutException();
            int count = write ? client.write(bytes) : client.read(bytes);
            if (count < 0) throw new EOFException("Incomplete frame");
            if (count == 0) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) throw new java.net.SocketTimeoutException();
                selector.select(Math.max(1, remaining / 1_000_000));
                selector.selectedKeys().clear();
            }
        }
    }
    public Map<String, Object> read() throws IOException {
        var header = ByteBuffer.allocate(4);
        transfer(header, false); header.flip();
        int length = header.getInt();
        if (length < 1 || length > MAX_PAYLOAD + 1) throw new IOException("Invalid frame length");
        var payload = ByteBuffer.allocate(length);
        transfer(payload, false); payload.flip();
        if (payload.get() != 1) throw new IOException("Invalid tag");
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        return Json.decode(decoder.decode(payload).toString());
    }
    public void write(Object value) throws IOException {
        byte[] bytes = Json.bytes(value, MAX_PAYLOAD);
        if (bytes.length > MAX_PAYLOAD) throw new IOException("Output limit");
        var header = ByteBuffer.allocate(5).putInt(bytes.length + 1).put((byte) 1);
        header.flip(); transfer(header, true); transfer(ByteBuffer.wrap(bytes), true);
    }
    public void binary(byte[] bytes, int length) throws IOException {
        if (length < 1 || length > 65536 || length > bytes.length) throw new IOException("Invalid chunk");
        var header = ByteBuffer.allocate(5).putInt(length + 1).put((byte)2);
        header.flip(); transfer(header, true); transfer(ByteBuffer.wrap(bytes, 0, length), true);
    }
    @Override public void close() throws IOException { selector.close(); }
}
