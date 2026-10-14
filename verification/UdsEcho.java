import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;

/** Transport-only fixture; accepts exactly one bounded frame and exits. */
public final class UdsEcho {
    static void read(SocketChannel client, ByteBuffer buffer) throws Exception {
        while (buffer.hasRemaining()) {
            if (client.read(buffer) < 0) throw new java.io.EOFException("Incomplete frame");
        }
        buffer.flip();
    }
    public static void main(String[] args) throws Exception {
        Path socket = Path.of(args[0]);
        boolean bound = false;
        try (var listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            listener.bind(UnixDomainSocketAddress.of(socket));
            bound = true;
            System.out.println("ready");
            try (var client = listener.accept()) {
                var header = ByteBuffer.allocate(4);
                read(client, header);
                int length = header.getInt();
                if (length < 1 || length > 262145) throw new java.io.IOException("Invalid length");
                var payload = ByteBuffer.allocate(length);
                read(client, payload);
                if (payload.get(0) != 1) throw new java.io.IOException("Invalid tag");
                header.rewind();
                while (header.hasRemaining()) client.write(header);
                while (payload.hasRemaining()) client.write(payload);
            }
        } finally {
            if (bound) Files.deleteIfExists(socket);
        }
    }
}
