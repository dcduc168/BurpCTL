import java.net.ServerSocket;
import java.net.InetAddress;
import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

/** Authorized loopback-only integration corpus; never invokes a remote target. */
public final class TrafficFixture {
    public static byte[] body(int id) {
        return switch (id % 10) {
            case 0 -> ("Tiếng Việt 🦀 fixture " + id).getBytes(StandardCharsets.UTF_8);
            case 1 -> new byte[] {0, 1, 2, 27, 91, 51, 49, 109, 13, 10, (byte)255};
            case 2 -> new byte[] {(byte)0xc3, 0x28, (byte)0xfe, (byte)0xff};
            case 3 -> Base64.getDecoder().decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aX1sAAAAASUVORK5CYII=");
            case 4 -> ("%PDF-1.4\r\n1 0 obj<</Type/Catalog>>endobj\r\n%%EOF " + id).getBytes(StandardCharsets.US_ASCII);
            case 5 -> new byte[] {80, 75, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            case 6 -> ("--bctl\r\nContent-Disposition: form-data; name=\"file\"; filename=\"f.bin\"\r\n\r\n\u0000\u001bdata\r\n--bctl--\r\n" + id).getBytes(StandardCharsets.UTF_8);
            case 7 -> ("\u202e\u2066line\n\r\tfixture " + id).getBytes(StandardCharsets.UTF_8);
            case 8 -> new byte[0];
            default -> {
                byte[] bytes = new byte[id == 99 ? 1048576 : 8192];
                for (int i = 0; i < bytes.length; i++) bytes[i] = (byte)(i * 31 + id);
                yield bytes;
            }
        };
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("hashes")) {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            var rows = new java.util.ArrayList<String>();
            for (int id = 0; id < 100; id++) {
                byte[] bytes = body(id);
                rows.add("{\"id\":" + id + ",\"size\":" + bytes.length + ",\"sha256\":\""
                        + java.util.HexFormat.of().formatHex(digest.digest(bytes)) + "\",\"prefix_sha256\":\""
                        + java.util.HexFormat.of().formatHex(digest.digest(java.util.Arrays.copyOf(bytes, Math.min(bytes.length, 4096)))) + "\"}");
            }
            System.out.println("[" + String.join(",", rows) + "]"); return;
        }
        if ((args.length != 1 && args.length != 2) || !args[0].equals("populate")) throw new IllegalArgumentException("Explicit populate required");
        int first = args.length == 2 ? Integer.parseInt(args[1]) : 0;
        if (first < 0 || first > 99) throw new IllegalArgumentException("Invalid start ID");
        var server = new ServerSocket(18123, 2, InetAddress.getByName("127.0.0.1"));
        var worker = new Thread(() -> {
            while (!server.isClosed()) {
                try (var socket = server.accept()) {
                    socket.setSoTimeout(5000);
                    var input = socket.getInputStream();
                    var headers = new ByteArrayOutputStream();
                    int marker = 0;
                    while (marker != 4 && headers.size() < 16384) {
                        int value = input.read();
                        if (value < 0) throw new java.io.EOFException();
                        headers.write(value);
                        marker = switch (marker) {
                            case 0 -> value == 13 ? 1 : 0;
                            case 1 -> value == 10 ? 2 : 0;
                            case 2 -> value == 13 ? 3 : 0;
                            default -> value == 10 ? 4 : 0;
                        };
                    }
                    if (marker != 4) throw new java.io.IOException("Header budget");
                    String[] lines = headers.toString(StandardCharsets.US_ASCII).split("\r\n");
                    String path = lines[0].split(" ")[1];
                    int id = Integer.parseInt(path.substring("/fixture/".length()));
                    if (id < 0 || id >= 100) throw new java.io.IOException("Invalid fixture ID");
                    int length = 0;
                    for (String line : lines) if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:"))
                        length = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
                    if (length < 0 || length > 1048576 || input.readNBytes(length).length != length)
                        throw new java.io.IOException("Invalid request body");
                    byte[] output = body(id);
                    var stream = socket.getOutputStream();
                    stream.write(("HTTP/1.1 " + (id % 3 == 0 ? "201 Created" : "200 OK")
                            + "\r\nContent-Type: application/octet-stream\r\nConnection: close\r\nContent-Length: "
                            + output.length + "\r\nX-BurpCTL-Fixture: " + id + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    stream.write(output);
                } catch (Exception error) {
                    if (!server.isClosed()) throw new RuntimeException(error);
                }
            }
        }, "burpctl-loopback-fixture");
        worker.setDaemon(true); worker.start();
        try (var client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(3))
                .proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1", 8080))).build()) {
            for (int id = first; id < 100; id++) {
                var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:18123/fixture/" + id))
                        .timeout(Duration.ofSeconds(30)).header("Content-Type", "application/octet-stream")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(body(id))).build();
                var response = client.send(request, HttpResponse.BodyHandlers.ofByteArray());
                if (!java.util.Arrays.equals(response.body(), body(id))) throw new AssertionError("Fixture changed: " + id);
            }
            System.out.println("PASS: " + (100 - first) + " synthetic loopback requests/responses via Burp 127.0.0.1:8080");
        } finally { server.close(); worker.join(2000); }
    }
}
