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
    static void runtimeOwnership() throws Exception {
        Path directory = Files.createTempDirectory(dev.burpctl.runtime.PrivateFiles.runtimeRoot().getParent(), "bctl-owner-");
        var security = new dev.burpctl.runtime.PrivateFiles(directory);
        var user = directory.getFileSystem().getUserPrincipalLookupService().lookupPrincipalByName(System.getProperty("user.name"));
        var original = Files.getOwner(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS);
        try {
            if (!original.equals(user)) {
                try { security.directory(directory); throw new AssertionError("Existing foreign owner accepted"); }
                catch (java.io.IOException expected) { }
                require(Files.getOwner(directory, java.nio.file.LinkOption.NOFOLLOW_LINKS).equals(original), "Existing owner must not be changed");
            }
            Files.delete(directory);
            security.newDirectory(directory);
            security.file(directory.resolve("sample"), "fixture");
            security.check(directory);
            security.check(directory.resolve("sample"));
            require(Files.getOwner(directory).equals(user) && Files.getOwner(directory.resolve("sample")).equals(user), "New runtime objects use the current user owner");
            if (!System.getProperty("os.name").startsWith("Windows")) {
                Path sample = directory.resolve("sample");
                var privateMode = java.nio.file.attribute.PosixFilePermissions.fromString("rw-------");
                Files.setPosixFilePermissions(sample, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));
                try { security.check(sample); throw new AssertionError("Public credential accepted"); }
                catch (java.io.IOException expected) { }
                Files.setPosixFilePermissions(sample, privateMode);
                Path link = directory.resolve("link");
                Files.createSymbolicLink(link, sample);
                try { security.check(link); throw new AssertionError("Symlink accepted"); }
                catch (java.io.IOException expected) { }
                finally { Files.delete(link); }
                Files.createLink(link, sample);
                try { security.check(sample); throw new AssertionError("Hard-linked credential accepted"); }
                catch (java.io.IOException expected) { }
                finally { Files.delete(link); }
                Files.setPosixFilePermissions(directory, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
                try { security.directory(directory); throw new AssertionError("Public directory accepted"); }
                catch (java.io.IOException expected) { }
                require(Files.getPosixFilePermissions(directory).contains(java.nio.file.attribute.PosixFilePermission.GROUP_READ), "Unsafe existing mode was repaired");
                Files.setPosixFilePermissions(directory, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
            }
        } finally { Files.deleteIfExists(directory.resolve("sample")); Files.deleteIfExists(directory); }
    }
    static void partialFrameDeadline() throws Exception {
        Path directory = Files.createTempDirectory(dev.burpctl.runtime.PrivateFiles.runtimeRoot().getParent(), "bctl-time-");
        Path socket = directory.resolve("s");
        try (var listener = java.nio.channels.ServerSocketChannel.open(StandardProtocolFamily.UNIX);
             var client = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            listener.bind(UnixDomainSocketAddress.of(socket));
            client.connect(UnixDomainSocketAddress.of(socket));
            long started = System.nanoTime();
            try (var peer = listener.accept(); var frames = new Frames(client, 100)) {
                peer.write(java.nio.ByteBuffer.wrap(new byte[]{0}));
                try { frames.read(); throw new AssertionError("Partial frame ignored deadline"); }
                catch (java.net.SocketTimeoutException expected) {
                    long elapsed = System.nanoTime() - started;
                    require(elapsed >= 80_000_000L && elapsed < 2_000_000_000L, "Partial-frame timeout timing");
                }
            }
        } finally { Files.deleteIfExists(socket); Files.delete(directory); }
    }
    static void malformed(Path socket, byte[] bytes) throws Exception {
        int count = calls.get();
        try (var client = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            client.connect(UnixDomainSocketAddress.of(socket));
            var input = java.nio.ByteBuffer.wrap(bytes);
            while (input.hasRemaining()) client.write(input);
            client.shutdownOutput(); client.configureBlocking(false);
            long deadline = System.nanoTime() + 2_000_000_000L;
            int received;
            do {
                received = client.read(java.nio.ByteBuffer.allocate(1));
                if (received == 0) Thread.sleep(10);
            } while (received == 0 && System.nanoTime() < deadline);
            require(received == -1, "Malformed frame must close without a response");
        }
        require(calls.get() == count, "Malformed frame invoked Montoya");
    }
    public static void main(String[] args) throws Exception {
        runtimeOwnership();
        partialFrameDeadline();
        Path root = dev.burpctl.runtime.PrivateFiles.runtimeRoot().resolve("r");
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
            for (byte[] invalid : java.util.List.of(new byte[]{0, 0, 0, 0}, new byte[]{0, 4, 0, 2},
                    new byte[]{0, 0, 0, 1, 2}, new byte[]{0, 0, 0, 4, 1, '{'})) malformed(socket, invalid);
            var envelope = new java.util.LinkedHashMap<String, Object>();
            envelope.put("version", Map.of("major", 1, "minor", 0)); envelope.put("id", "smoke");
            envelope.put("auth", token); envelope.put("method", "status"); envelope.put("params", Map.of());
            envelope.put("context", Map.of("instance_id", metadata.get("instance_id"), "project_id", "fixture-project"));
            require(Boolean.TRUE.equals(request(socket, envelope).get("ok")), "Authenticated status");
            var screenshot = new java.util.LinkedHashMap<>(envelope); screenshot.put("method", "repeater.screenshot");
            int beforeScreenshot = calls.get();
            require("PERMISSION_DENIED".equals(((Map<?, ?>)request(socket, screenshot).get("error")).get("code")), "Screenshot default denied");
            require(calls.get() == beforeScreenshot, "Denied screenshot invoked Montoya");
            require(Server.EXTENSION_VERSION.equals(Server.class.getPackage().getImplementationVersion()), "Version comes from packaged build metadata");
            require(Server.EXTENSION_VERSION.equals(((Map<?, ?>)request(socket, envelope).get("result")).get("extension_version")), "Status reports packaged version");
            for (String input : java.util.List.of("{\"id\":1,\"part\":null}", "{\"id\":1,\"part\":\"response.body\",\"encoding\":null}")) {
                var invalid = new java.util.LinkedHashMap<>(envelope);
                invalid.put("method", "history.get"); invalid.put("params", Json.decode(input));
                int count = calls.get();
                require("INVALID_ARGUMENT".equals(((Map<?, ?>)request(socket, invalid).get("error")).get("code")), "Null enums rejected");
                require(calls.get() == count, "Null enums invoked Montoya");
            }
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
            for (String json : java.util.List.of("{\"a\":1,\"a\":2}", "{}{}", "{\"a\":1.5}", "{\"a\":9223372036854775808}",
                    "{\"\\ud800\":0}", "{\"\\udc00\":0}", "{\"a\":\"\\ud800\"}", "{\"a\":\"\\udc00\"}")) {
                try { Json.decode(json); throw new AssertionError("Invalid JSON accepted"); }
                catch (java.io.IOException expected) {}
            }
            require(Json.decode("{\"\\ud83d\\ude00\":\"\\ud83d\\ude00\"}").size() == 1, "Valid Unicode pair accepted");
            System.out.println("PASS: partial-frame deadline, malformed framing, overload BUSY, status, auth/context/version/method/params denial before Montoya, strict JSON");
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
