import java.net.StandardProtocolFamily;
import java.nio.channels.ServerSocketChannel;

/** Run before building features: the deployed Windows JVM must support AF_UNIX. */
public final class UdsSupport {
    public static void main(String[] args) throws Exception {
        System.out.println("java=" + Runtime.version() + " os=" + System.getProperty("os.name"));
        try (var listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX)) {
            System.out.println("AF_UNIX listener supported");
        }
    }
}
