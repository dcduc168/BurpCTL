import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.core.ByteArray;
import dev.burpctl.features.History;
import dev.burpctl.features.Body;
import dev.burpctl.ipc.Fault;
import dev.burpctl.ipc.Json;
import dev.burpctl.security.Policy;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/** Executable feature/resource check, with no unit-test framework. */
public final class HistorySmoke {
    static final AtomicInteger bodies = new AtomicInteger();
    static final AtomicInteger reads = new AtomicInteger();
    static final AtomicInteger responses = new AtomicInteger();
    static final AtomicInteger backend = new AtomicInteger();
    static final AtomicInteger requests = new AtomicInteger();
    static final AtomicInteger scopeChecks = new AtomicInteger();
    interface Call { Object invoke(String name, Object[] arguments); }
    static <T> T proxy(Class<T> type, Call handler) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[]{type},
                (value, method, args) -> handler.invoke(method.getName(), args)));
    }
    static ByteArray bytes(byte[] payload) {
        return proxy(ByteArray.class, (name, args) -> switch (name) {
            case "length" -> payload.length;
            case "getByte" -> { reads.incrementAndGet(); yield payload[(Integer)args[0]]; }
            default -> throw new AssertionError("Unexpected byte allocation: " + name);
        });
    }
    static ProxyHttpRequestResponse row(int id) {
        byte[] payload = TrafficFixture.body(id);
        var service = proxy(burp.api.montoya.http.HttpService.class, (name, args) -> switch (name) {
            case "host" -> "127.0.0.1";
            case "port" -> 18123;
            case "secure" -> false;
            default -> throw new AssertionError(name);
        });
        var request = proxy(burp.api.montoya.http.message.requests.HttpRequest.class, (name, args) -> switch (name) {
            case "url" -> "http://127.0.0.1:18123/fixture/" + id;
            case "pathWithoutQuery" -> "/fixture/" + id;
            case "method" -> "POST";
            case "httpService" -> service;
            case "body", "toByteArray" -> { bodies.incrementAndGet(); yield bytes(payload); }
            default -> throw new AssertionError("Unexpected request access: " + name);
        });
        var response = proxy(burp.api.montoya.http.message.responses.HttpResponse.class, (name, args) -> switch (name) {
            case "statusCode" -> (short)(id % 3 == 0 ? 201 : 200);
            case "body", "toByteArray" -> { bodies.incrementAndGet(); yield bytes(payload); }
            default -> throw new AssertionError("Unexpected response access: " + name);
        });
        return proxy(ProxyHttpRequestResponse.class, (name, args) -> switch (name) {
            case "id" -> id;
            case "finalRequest" -> { requests.incrementAndGet(); yield request; }
            case "hasResponse" -> id != 98;
            case "response" -> { responses.incrementAndGet(); yield response; }
            default -> throw new AssertionError("Deprecated/unexpected history access: " + name);
        });
    }
    static void require(boolean value, String description) { if (!value) throw new AssertionError(description); }
    public static void main(String[] args) throws Exception {
        var rows = java.util.stream.IntStream.range(0, 100).mapToObj(HistorySmoke::row).toList();
        var scoped = new java.util.concurrent.atomic.AtomicBoolean(true);
        var api = proxy(MontoyaApi.class, (name, arguments) -> switch (name) {
            case "scope" -> proxy(burp.api.montoya.scope.Scope.class, (method, values) -> {
                scopeChecks.incrementAndGet(); return scoped.get();
            });
            case "proxy" -> { backend.incrementAndGet(); yield proxy(burp.api.montoya.proxy.Proxy.class, (method, values) -> {
                require(method.equals("history") && values.length == 1, "Filtered API only");
                var filter = (ProxyHistoryFilter)values[0];
                return rows.parallelStream().filter(filter::matches).toList();
            }); }
            default -> throw new AssertionError(name);
        });
        var policy = new Policy(); var history = new History(api, policy);
        try { history.query(Map.of(), false); throw new AssertionError("Default permission"); }
        catch (Fault error) { require(error.code.equals("PERMISSION_DENIED") && backend.get() == 0, "Policy before backend"); }
        policy.metadata.set(true);
        var result = history.query(Map.of("fields", List.of("id", "status"), "limit", 10L), false);
        var items = (List<?>)((Map<?, ?>)result.result()).get("items");
        require(items.size() == 10 && bodies.get() == 0 && reads.get() == 0, "Bounded metadata without body access");
        require(items.stream().allMatch(item -> ((Map<?, ?>)item).keySet().equals(java.util.Set.of("id", "status"))), "Exact projection");
        responses.set(0);
        requests.set(0);
        history.query(Map.of("fields", List.of("id"), "limit", 100L), false);
        require(responses.get() == 0, "Unselected status not accessed");
        require(requests.get() == 200, "ID-only projection adds no request access beyond scope checks");
        requests.set(0);
        history.query(Map.of("fields", List.of("method", "host", "path", "port", "secure"), "limit", 100L), false);
        require(requests.get() == 300 && bodies.get() == 0, "Request metadata resolved once per projected row without body access");
        result = history.query(Map.of("fields", List.of("id", "status"), "limit", 100L), false);
        require(Json.decode(Json.encode(result.result())).toString().contains("status=null"), "No response is null");
        scopeChecks.set(0);
        require(((List<?>)((Map<?, ?>)history.query(Map.of("filters", Map.of("host", "other")), false).result()).get("items")).isEmpty(), "Empty success");
        require(scopeChecks.get() == 0 && bodies.get() == 0, "Nonmatching hosts skip URL scope work and bodies");
        for (var filter : List.of(Map.of("method", "GET"), Map.of("path_contains", "/missing/"), Map.of("status", 404L))) {
            scopeChecks.set(0);
            result = history.query(Map.of("filters", filter), false);
            require(((List<?>)((Map<?, ?>)result.result()).get("items")).isEmpty(), "Nonmatching filter returns empty success");
            require(scopeChecks.get() == 0 && bodies.get() == 0, "Nonmatching metadata skips URL scope work and bodies");
        }
        scopeChecks.set(0);
        requests.set(0);
        history.query(Map.of("id", 0L, "fields", List.of("id")), true);
        require(scopeChecks.get() == 2 && requests.get() == 2, "Get checks scope in callback and before projection");
        try { history.query(Map.of("id", 0L, "part", "response.body"), true); throw new AssertionError("Raw permission"); }
        catch (Fault error) { require(error.code.equals("PERMISSION_DENIED"), "Raw separately denied"); }
        scoped.set(false);
        require(((List<?>)((Map<?, ?>)history.query(Map.of("filters", Map.of("host", "127.0.0.1")), false).result()).get("items")).isEmpty(), "Matching host still requires scope");
        try { history.query(Map.of("id", 0L), true); throw new AssertionError("Scope bypass"); }
        catch (Fault error) { require(error.code.equals("OUT_OF_SCOPE"), "Out-of-scope ID denied"); }
        scoped.set(true);
        policy.raw.set(true);
        for (int id = 0; id < 100; id++) {
            if (id == 98) continue;
            result = history.query(Map.of("id", (long)id, "part", "response.body", "encoding", "base64"), true);
            var item = (Map<?, ?>)((Map<?, ?>)result.result()).get("item");
            byte[] expected = TrafficFixture.body(id);
            require(java.util.Arrays.equals(java.util.Arrays.copyOf(expected, Math.min(expected.length, 4096)),
                    java.util.Base64.getDecoder().decode((String)item.get("data"))), "Base64 byte integrity");
            Json.decode(Json.encode(result.result()));
        }
        try { history.query(Map.of("id", 2L, "part", "response.body"), true); throw new AssertionError("Lossy UTF-8"); }
        catch (Fault error) { require(error.code.equals("INVALID_ARGUMENT"), "Invalid UTF-8 rejected"); }
        try { history.query(Map.of("id", 98L, "part", "response.body"), true); throw new AssertionError("Missing response"); }
        catch (Fault error) { require(error.code.equals("NOT_FOUND"), "Missing response precise"); }
        for (int id = 0; id < 100; id++) {
            result = history.query(Map.of("id", (long)id, "part", "request.body", "encoding", "raw"), true);
            try (var export = (History.Export)result.result()) {
                require(java.util.Arrays.equals(TrafficFixture.body(id), Body.prefix(export.bytes(), export.bytes().length())), "Raw exact API bytes");
                try { history.query(Map.of(), false); throw new AssertionError("Stream scan concurrency"); }
                catch (Fault error) { require(error.code.equals("BUSY"), "Scan permit retained during export"); }
            }
        }
        System.out.println("PASS: 100 safe metadata records; concurrent callback cap/projection; no implicit bytes; 99 Base64 and 100 raw comparisons; UTF-8/no-response/policy/concurrency checks");
    }
}
