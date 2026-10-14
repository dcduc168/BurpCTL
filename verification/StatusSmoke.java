import burp.api.montoya.MontoyaApi;
import dev.burpctl.runtime.Server;
import dev.burpctl.ipc.Frames;
import dev.burpctl.ipc.Json;
import java.lang.reflect.Proxy;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Focused smoke check of production IPC/security/lifecycle; Montoya is a stub. */
public final class StatusSmoke {
    static final AtomicInteger calls = new AtomicInteger();
    static Object stub(Class<?> type) {
        return Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type}, (proxy, method, arguments) -> {
            calls.incrementAndGet();
            if (method.getName().equals("id")) return "fixture-project";
            if (method.getName().equals("toString")) return "fixture-version";
            if (method.getReturnType().isInterface()) return stub(method.getReturnType());
            throw new AssertionError("Unexpected Montoya call: " + method.getName());
        });
    }
    static Map<String, Object> request(Path socket, Object request) throws Exception {
        try (var client = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            client.connect(UnixDomainSocketAddress.of(socket));
            try (var frames = new Frames(client)) { frames.write(request); return frames.read(); }
        }
    }
    static void require(boolean value, String message) { if (!value) throw new AssertionError(message); }
    public static void main(String[] args) throws Exception {
        Path root = Path.of(System.getenv("LOCALAPPDATA"), "burpctl", "r");
        var before = Files.exists(root) ? directories(root) : java.util.Set.<Path>of();
        var server = new Server((MontoyaApi) stub(MontoyaApi.class));
        Path owned = null;
        try {
            server.start();
            var after = directories(root); after.removeAll(before);
            require(after.size() == 1, "One new runtime directory");
            owned = after.iterator().next();
            var metadata = Json.decode(Files.readString(owned.resolve("instance.json")));
            String token = Files.readString(owned.resolve("credential"));
            Path socket = owned.resolve("s");
            var envelope = new java.util.LinkedHashMap<String, Object>();
            envelope.put("version", Map.of("major", 1, "minor", 0)); envelope.put("id", "smoke");
            envelope.put("auth", token); envelope.put("method", "status"); envelope.put("params", Map.of());
            envelope.put("context", Map.of("instance_id", metadata.get("instance_id"), "project_id", "fixture-project"));
            require(Boolean.TRUE.equals(request(socket, envelope).get("ok")), "Authenticated status");
            var namedId = new java.util.LinkedHashMap<>(envelope); namedId.put("id", "invalid");
            require(Boolean.TRUE.equals(request(socket, namedId).get("ok")), "Opaque IDs have no reserved sentinel value");
            for (String failure : java.util.List.of("AUTH_FAILED", "STALE_REFERENCE", "INCOMPATIBLE_PROTOCOL", "UNKNOWN_METHOD", "INVALID_ARGUMENT")) {
                var invalid = new java.util.LinkedHashMap<>(envelope);
                switch (failure) {
                    case "AUTH_FAILED" -> invalid.put("auth", "0".repeat(64));
                    case "STALE_REFERENCE" -> invalid.put("context", Map.of("instance_id", "other", "project_id", "fixture-project"));
                    case "INCOMPATIBLE_PROTOCOL" -> invalid.put("version", Map.of("major", 2, "minor", 0));
                    case "UNKNOWN_METHOD" -> invalid.put("method", "http.send");
                    case "INVALID_ARGUMENT" -> invalid.put("params", Map.of("unsafe", true));
                }
                int count = calls.get();
                var response = request(socket, invalid);
                require(failure.equals(((Map<?, ?>) response.get("error")).get("code")), failure);
                require(calls.get() == count, "Rejected request invoked Montoya");
                require(!Json.encode(response).contains(token), "Credential echoed");
            }
            try (var first = SocketChannel.open(StandardProtocolFamily.UNIX);
                 var second = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                first.connect(UnixDomainSocketAddress.of(socket));
                second.connect(UnixDomainSocketAddress.of(socket));
                Thread.sleep(100);
                int count = calls.get();
                var busy = request(socket, envelope);
                require("BUSY".equals(((Map<?, ?>)busy.get("error")).get("code")), "Authenticated overload reports BUSY");
                require(calls.get() == count, "Overload invoked Montoya");
            }
            try (var other = new Server((MontoyaApi)stub(MontoyaApi.class))) {
                var initial = directories(root);
                other.start();
                var added = directories(root); added.removeAll(initial);
                require(added.size() == 1, "Same-project instance directory unique");
                var otherDirectory = added.iterator().next();
                var invalid = new java.util.LinkedHashMap<>(envelope);
                invalid.put("auth", Files.readString(otherDirectory.resolve("credential")));
                int count = calls.get();
                var response = request(otherDirectory.resolve("s"), invalid);
                require("STALE_REFERENCE".equals(((Map<?, ?>)response.get("error")).get("code")), "Same project different instance denied");
                require(calls.get() == count, "Cross-instance request invoked Montoya");
            }
            for (String json : java.util.List.of("{\"a\":1,\"a\":2}", "{}{}", "{\"a\":1.5}", "{\"a\":9223372036854775808}")) {
                try { Json.decode(json); throw new AssertionError("Invalid JSON accepted"); }
                catch (java.io.IOException expected) {}
            }
            System.out.println("PASS: overload BUSY, status, auth/context/version/method/params denial before Montoya, strict JSON");
        } finally { server.close(); }
        require(owned != null && !Files.exists(owned), "Owned files removed on close");
        long deadline = System.nanoTime() + 2_000_000_000L;
        while (Thread.getAllStackTraces().keySet().stream().anyMatch(thread -> thread.getName().startsWith("burpctl-")) && System.nanoTime() < deadline)
            Thread.sleep(10);
        require(Thread.getAllStackTraces().keySet().stream().noneMatch(thread -> thread.getName().startsWith("burpctl-")), "Owned threads stopped on close");
        server.close();
        System.out.println("PASS: close idempotence and runtime cleanup");
    }
    static java.util.Set<Path> directories(Path root) throws Exception {
        try (var stream = Files.list(root)) { return stream.collect(java.util.stream.Collectors.toSet()); }
    }
}
