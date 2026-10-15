package dev.burpctl.runtime;

import burp.api.montoya.MontoyaApi;
import dev.burpctl.ipc.Frames;
import dev.burpctl.ipc.Json;
import dev.burpctl.ipc.Fault;
import dev.burpctl.security.Policy;
import dev.burpctl.features.Scope;
import dev.burpctl.features.History;
import dev.burpctl.features.Screenshot;
import java.io.IOException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public final class Server implements AutoCloseable {
    public static final Map<String, Object> VERSION = Map.of("major", 1, "minor", 0);
    public static final String EXTENSION_VERSION = java.util.Objects.requireNonNullElse(
            Server.class.getPackage().getImplementationVersion(), "development");
    private final MontoyaApi api;
    private final Policy policy;
    private final History history;
    private final Screenshot screenshot;
    private final Set<Frames> activeFrames = ConcurrentHashMap.newKeySet();
    private final Set<SocketChannel> clients = ConcurrentHashMap.newKeySet();
    private final String instance = random(16);
    private final String token = random(32);
    private String project;
    private Path directory;
    private ServerSocketChannel listener;
    private ThreadPoolExecutor workers;
    private ThreadPoolExecutor rejector;
    private volatile boolean closed;
    public Server(MontoyaApi api) { this(api, new Policy()); }
    public Server(MontoyaApi api, Policy policy) { this.api = api; this.policy = policy; this.history = new History(api, policy); this.screenshot = new Screenshot(api, policy); }
    private static String random(int length) {
        byte[] bytes = new byte[length]; new SecureRandom().nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
    public synchronized void start() throws IOException {
        if (closed) return;
        String local = System.getenv("LOCALAPPDATA");
        if (local == null) throw new IOException("LOCALAPPDATA unavailable");
        Path base = Path.of(local).toRealPath();
        var security = new PrivateFiles(base);
        Path root = base.resolve("burpctl");
        security.directory(root);
        Path runtime = root.resolve("r");
        security.directory(runtime);
        Path candidate = runtime.resolve(instance.substring(0, 12));
        security.newDirectory(candidate);
        directory = candidate;
        Path socket = directory.resolve("s");
        if (socket.toString().getBytes(StandardCharsets.UTF_8).length > 100) throw new IOException("UDS path too long");
        project = api.project().id();
        if (project == null || project.length() > 128) throw new IOException("Invalid project identity");
        listener = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
        listener.bind(UnixDomainSocketAddress.of(socket));
        // Socket ACL inherits only current-user access from the private directory.
        var socketAcl = Files.getFileAttributeView(socket, java.nio.file.attribute.AclFileAttributeView.class);
        var parentAcl = Files.getFileAttributeView(directory, java.nio.file.attribute.AclFileAttributeView.class);
        if (socketAcl == null || socketAcl.getAcl().isEmpty() || !socketAcl.getOwner().equals(parentAcl.getOwner()) ||
                socketAcl.getAcl().stream().anyMatch(e -> e.type() != java.nio.file.attribute.AclEntryType.ALLOW || !e.principal().equals(parentAclOwner(parentAcl))))
            throw new IOException("Socket ACL is not private");
        security.file(directory.resolve("credential"), token);
        security.file(directory.resolve("instance.json"), Json.encode(Map.of(
                "instance_id", instance, "project_id", project, "socket_path", socket.toString(),
                "protocol_major", 1, "created_at", Instant.now().toString(), "pid", ProcessHandle.current().pid())));
        workers = new ThreadPoolExecutor(0, 2, 30, TimeUnit.SECONDS, new SynchronousQueue<>(), job -> {
            var thread = new Thread(job, "burpctl-client"); thread.setDaemon(true); return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
        rejector = new ThreadPoolExecutor(0, 1, 1, TimeUnit.SECONDS, new SynchronousQueue<>(), job -> {
            var thread = new Thread(job, "burpctl-overload"); thread.setDaemon(true); return thread;
        }, new ThreadPoolExecutor.AbortPolicy());
        var acceptor = new Thread(this::accept, "burpctl-accept");
        acceptor.setDaemon(true); acceptor.start();
    }
    private static java.nio.file.attribute.UserPrincipal parentAclOwner(java.nio.file.attribute.AclFileAttributeView view) {
        try { return view.getOwner(); } catch (IOException e) { throw new java.io.UncheckedIOException(e); }
    }
    private void accept() {
        while (!closed) {
            try {
                SocketChannel client = listener.accept();
                synchronized (this) {
                    if (closed) { client.close(); break; }
                    clients.add(client);
                    try { workers.execute(() -> serve(client)); }
                    catch (java.util.concurrent.RejectedExecutionException e) {
                        try { rejector.execute(() -> reject(client)); }
                        catch (java.util.concurrent.RejectedExecutionException full) { clients.remove(client); client.close(); }
                    }
                }
            } catch (IOException e) { if (!closed) close(); }
        }
    }
    private void reject(SocketChannel client) {
        try (client; var frames = new Frames(client, 1000)) {
            var request = frames.read();
            String id = request.get("id") instanceof String value && value.length() <= 128 ? value : "invalid";
            Object supplied = request.get("auth");
            boolean authenticated = supplied instanceof String secret && secret.length() == 64 && MessageDigest.isEqual(
                    token.getBytes(StandardCharsets.US_ASCII), secret.getBytes(StandardCharsets.UTF_8));
            frames.write(error(id, authenticated ? "BUSY" : "AUTH_FAILED"));
        } catch (IOException | RuntimeException ignored) { }
        finally { clients.remove(client); }
    }
    private void serve(SocketChannel client) {
        try (client; var frames = new Frames(client)) {
            activeFrames.add(frames);
            try {
                if (closed) return;
                Map<String, Object> request = frames.read();
                String id = request.get("id") instanceof String value && value.length() <= 128 ? value : "invalid";
                Object response;
                try { response = dispatch(request, id); }
                catch (Fault error) { response = error(id, error.code, error.getMessage()); }
                catch (RuntimeException error) { response = error(id, "INTERNAL_ERROR"); }
                if (response instanceof RawResponse raw) {
                    try (var export = raw.export()) { stream(frames, raw); }
                } else if (response instanceof ScreenshotResponse image) {
                    try (var export = image.export()) {
                        sendStream(frames, image.id(), image.budget(), export.bytes().length, "swing_repeater_png",
                                Map.of("provenance", Map.of("instance_id", instance, "project_id", project),
                                        "representation", "repeater_viewport", "transformation", "swing_rendered_png",
                                        "media_type", "image/png", "width", export.width(), "height", export.height()),
                                index -> export.bytes()[index], this::checkScreenshot);
                    }
                } else {
                    if (response instanceof Map<?, ?> envelope && Boolean.TRUE.equals(envelope.get("ok")) &&
                            request.get("method") instanceof String method && method.startsWith("history.")) {
                        try {
                            policy.requireMetadata();
                            if (request.get("params") instanceof Map<?, ?> params && params.containsKey("part")) policy.requireRaw();
                        } catch (Fault e) { response = error(id, e.code); }
                    }
                    frames.write(response);
                }
            } finally { activeFrames.remove(frames); }
        } catch (IOException | RuntimeException ignored) {
            // Malformed framing has no trustworthy request ID; close without diagnostics containing client data.
        } finally { clients.remove(client); }
    }
    private Object dispatch(Map<String, Object> request, String id) {
        if (closed) throw new Fault("FEATURE_UNAVAILABLE");
        Object supplied = request.get("auth");
        if (!(supplied instanceof String secret) || secret.length() != 64 || !MessageDigest.isEqual(
                token.getBytes(StandardCharsets.US_ASCII), secret.getBytes(StandardCharsets.UTF_8))) throw new Fault("AUTH_FAILED");
        keys(request, Set.of("version", "id", "auth", "method", "params", "context"));
        if (!(request.get("id") instanceof String requestId) || requestId.length() > 128) throw new Fault("INVALID_ARGUMENT");
        var version = object(request.get("version"));
        keys(version, Set.of("major", "minor"));
        if (!Long.valueOf(1).equals(version.get("major"))) throw new Fault("INCOMPATIBLE_PROTOCOL");
        if (!Long.valueOf(0).equals(version.get("minor"))) throw new Fault("INCOMPATIBLE_PROTOCOL");
        var context = object(request.get("context")); keys(context, Set.of("instance_id", "project_id"));
        if (!instance.equals(context.get("instance_id")) || !project.equals(context.get("project_id"))) throw new Fault("STALE_REFERENCE");
        var params = object(request.get("params"));
        long budget = params.getOrDefault("max_bytes", 32768L) instanceof Long number ? number : -1;
        if (budget < 1024 || budget > Frames.MAX_PAYLOAD) throw new Fault("INVALID_ARGUMENT");
        if (!(request.get("method") instanceof String method)) throw new Fault("INVALID_ARGUMENT");
        if (!java.util.Set.of("status", "scope.check", "history.list", "history.get", "repeater.screenshot").contains(method)) throw new Fault("UNKNOWN_METHOD");
        keys(params, switch (method) {
            case "scope.check" -> Set.of("max_bytes", "url");
            case "history.list" -> Set.of("max_bytes", "limit", "fields", "filters");
            case "history.get" -> Set.of("max_bytes", "id", "fields", "part", "encoding", "body_max_bytes");
            default -> Set.of("max_bytes");
        });
        if (method.equals("history.list") || method.equals("history.get")) History.validate(params, method.equals("history.get"));
        if (method.equals("scope.check")) Scope.url(params.get("url"));
        if (method.startsWith("history.")) policy.requireMetadata();
        if (method.equals("history.get") && params.containsKey("part")) policy.requireRaw();
        if (method.equals("repeater.screenshot")) policy.requireScreenshot();
        if (!project.equals(api.project().id())) throw new Fault("STALE_REFERENCE");
        if (method.equals("repeater.screenshot")) return new ScreenshotResponse(id, screenshot.capture(this::checkScreenshot), (int)budget);
        Object result;
        var meta = new java.util.LinkedHashMap<String, Object>(Map.of("complete", true, "truncated", false));
        if (method.equals("scope.check")) result = new Scope(api).check(params);
        else if (method.equals("history.list") || method.equals("history.get")) {
            var query = history.query(params, method.equals("history.get"));
            if (query.result() instanceof History.Export export) return new RawResponse(id, export, (int)budget);
            result = query.result(); meta.putAll(query.meta());
            meta.put("provenance", Map.of("instance_id", instance, "project_id", project));
        } else result = Map.of("instance_id", instance, "project_id", project, "extension_version", EXTENSION_VERSION,
                "burp_version", api.burpSuite().version().toString(), "methods", java.util.List.of("status", "scope.check", "history.list", "history.get", "repeater.screenshot"),
                "permissions", Map.of("history_metadata", policy.metadata.get(), "history_raw", policy.raw.get(), "repeater_screenshot", policy.screenshot.get()));
        if (!project.equals(api.project().id())) throw new Fault("STALE_REFERENCE");
        if (method.startsWith("history.")) policy.requireMetadata();
        if (method.equals("history.get") && params.containsKey("part")) policy.requireRaw();
        var response = Map.of("version", VERSION, "id", id, "ok", true, "result", result, "meta", meta);
        Json.bytes(response, (int)budget);
        return response;
    }
    private record RawResponse(String id, History.Export export, int budget) {}
    private record ScreenshotResponse(String id, Screenshot.Export export, int budget) {}
    private void checkScreenshot() {
        if (closed) throw new Fault("FEATURE_UNAVAILABLE");
        policy.requireScreenshot();
        if (!project.equals(api.project().id())) throw new Fault("STALE_REFERENCE");
    }
    private void stream(Frames frames, RawResponse response) throws IOException {
        var export = response.export();
        String representation = export.part().startsWith("request") ? "final_" + export.part() : export.part();
        sendStream(frames, response.id(), response.budget(), export.bytes().length(),
                "montoya_" + representation.replace('.', '_'),
                Map.of("provenance", Map.of("instance_id", instance, "project_id", project, "history_id", export.row().id()),
                        "representation", representation, "transformation", "none"),
                index -> export.bytes().getByte(index), () -> {
                    export.check();
                    if (!project.equals(api.project().id())) throw new Fault("STALE_REFERENCE");
                });
    }
    private void sendStream(Frames frames, String id, int budget, int size, String source, Map<String, Object> meta,
                            java.util.function.IntUnaryOperator byteAt, Runnable check) throws IOException {
        boolean opened = false;
        try {
            check.run();
            var opening = Map.of("version", VERSION, "id", id, "ok", true,
                    "stream", Map.of("kind", "raw_bytes", "size_bytes", size, "chunk_max", 65536, "source", source), "meta", meta);
            Json.bytes(opening, budget);
            frames.write(opening); opened = true;
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[65536];
            int total = size;
            for (int offset = 0; offset < total;) {
                check.run();
                int length = Math.min(buffer.length, total - offset);
                for (int i = 0; i < length; i++) buffer[i] = (byte)byteAt.applyAsInt(offset + i);
                check.run();
                digest.update(buffer, 0, length);
                frames.binary(buffer, length); offset += length;
            }
            check.run();
            frames.write(Map.of("version", VERSION, "id", id, "stream_end",
                    Map.of("bytes_sent", total, "sha256", HexFormat.of().formatHex(digest.digest()), "complete", true)));
        } catch (Fault e) {
            frames.write(opened ? Map.of("version", VERSION, "id", id, "stream_error", Map.of("code", e.code)) : error(id, e.code));
        } catch (java.security.NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?>)) throw new Fault("INVALID_ARGUMENT");
        @SuppressWarnings("unchecked") var map = (Map<String, Object>) value;
        return map;
    }
    private static void keys(Map<String, Object> value, Set<String> allowed) {
        if (!allowed.containsAll(value.keySet())) throw new Fault("INVALID_ARGUMENT");
    }
    private static Object error(String id, String code) { return error(id, code, code.replace('_', ' ').toLowerCase(java.util.Locale.ROOT)); }
    private static Object error(String id, String code, String message) {
        return Map.of("version", VERSION, "id", id, "ok", false, "error",
                Map.of("code", code, "message", message, "retryable", code.equals("BUSY") || code.equals("TIMEOUT")));
    }
    @Override public synchronized void close() {
        if (closed) return;
        closed = true;
        if (listener != null) try { listener.close(); } catch (IOException ignored) {}
        clients.forEach(client -> { try { client.close(); } catch (IOException ignored) {} });
        activeFrames.forEach(frames -> { try { frames.close(); } catch (IOException ignored) {} });
        if (workers != null) workers.shutdownNow();
        if (rejector != null) rejector.shutdownNow();
        if (directory != null) {
            for (String name : java.util.List.of("instance.json", "credential", "s"))
                try { Files.deleteIfExists(directory.resolve(name)); } catch (IOException ignored) {}
            try { Files.deleteIfExists(directory); } catch (IOException ignored) {}
        }
    }
}
