package dev.burpctl.features;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import dev.burpctl.ipc.Fault;
import dev.burpctl.security.Policy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;

public final class History {
    public static final List<String> DEFAULT_FIELDS = List.of("id", "method", "host", "path", "status");
    public static final Set<String> FIELDS = Set.of("id", "method", "host", "path", "status", "has_response", "port", "secure");
    private final MontoyaApi api;
    private final Policy policy;
    private final Semaphore scan = new Semaphore(1);
    public History(MontoyaApi api, Policy policy) { this.api = api; this.policy = policy; }
    public static long integer(Object value, long minimum, long maximum) {
        if (!(value instanceof Long number) || number < minimum || number > maximum) throw new Fault("INVALID_ARGUMENT");
        return number;
    }
    public static List<String> fields(Map<String, Object> params) {
        Object supplied = params.getOrDefault("fields", DEFAULT_FIELDS);
        if (!(supplied instanceof List<?> fields) || fields.isEmpty() || fields.size() > FIELDS.size()) throw new Fault("INVALID_ARGUMENT");
        var result = new ArrayList<String>();
        for (Object field : fields) {
            if (!(field instanceof String name) || !FIELDS.contains(name) || result.contains(name)) throw new Fault("INVALID_ARGUMENT");
            result.add(name);
        }
        return result;
    }
    public static void validate(Map<String, Object> params, boolean get) {
        if (get && params.containsKey("part")) Body.validate(params); else fields(params);
        if (get) {
            integer(params.get("id"), 0, Integer.MAX_VALUE);
            if (!params.containsKey("part") && (params.containsKey("encoding") || params.containsKey("body_max_bytes"))) throw new Fault("INVALID_ARGUMENT");
        }
        else {
            integer(params.getOrDefault("limit", 10L), 1, 100);
            var filters = filters(params);
            if (!Set.of("host", "method", "status", "path_contains").containsAll(filters.keySet())) throw new Fault("INVALID_ARGUMENT");
            if (filters.containsKey("status")) integer(filters.get("status"), 100, 599);
            for (String name : List.of("host", "method", "path_contains")) if (filters.containsKey(name)) {
                Object value = filters.get(name);
                if (!(value instanceof String text) || text.isEmpty() || text.length() > 1024) throw new Fault("INVALID_ARGUMENT");
            }
        }
    }
    private static Map<String, Object> filters(Map<String, Object> params) {
        Object value = params.getOrDefault("filters", Map.of());
        if (!(value instanceof Map<?, ?>)) throw new Fault("INVALID_ARGUMENT");
        @SuppressWarnings("unchecked") var filters = (Map<String, Object>) value;
        return filters;
    }
    private boolean inScope(ProxyHttpRequestResponse row) {
        try { return api.scope().isInScope(row.finalRequest().url()); }
        catch (burp.api.montoya.http.message.requests.MalformedRequestException e) { return false; }
    }
    private boolean matches(ProxyHttpRequestResponse row, Map<String, Object> filters) {
        var request = row.finalRequest();
        if (!inScope(row)) return false;
        if (filters.containsKey("host") && !request.httpService().host().equalsIgnoreCase((String)filters.get("host"))) return false;
        if (filters.containsKey("method") && !request.method().equals(filters.get("method"))) return false;
        if (filters.containsKey("path_contains") && !request.pathWithoutQuery().contains((String)filters.get("path_contains"))) return false;
        if (filters.containsKey("status") && (!row.hasResponse() || row.response().statusCode() != (Long)filters.get("status"))) return false;
        return true;
    }
    public Query query(Map<String, Object> params, boolean get) {
        policy.requireMetadata();
        if (params.containsKey("part")) policy.requireRaw();
        validate(params, get);
        if (!scan.tryAcquire()) throw new Fault("BUSY");
        boolean exported = false;
        try {
            int limit = get ? 1 : (int)integer(params.getOrDefault("limit", 10L), 1, 100);
            var accepted = new AtomicInteger();
            var filters = get ? Map.<String, Object>of() : filters(params);
            long deadline = System.nanoTime() + 20_000_000_000L;
            var denied = new java.util.concurrent.atomic.AtomicBoolean();
            var expired = new java.util.concurrent.atomic.AtomicBoolean();
            var rows = api.proxy().history(row -> {
                if (System.nanoTime() >= deadline) { expired.set(true); return false; }
                if (!policy.metadata.get() || accepted.get() >= limit) return false;
                if (get && row.id() != (Long)params.get("id")) return false;
                if (get && !inScope(row)) { denied.set(true); return false; }
                try { if (!matches(row, filters)) return false; }
                catch (burp.api.montoya.http.message.requests.MalformedRequestException e) { return false; }
                int count;
                do {
                    count = accepted.get();
                    if (count >= limit) return false;
                } while (!accepted.compareAndSet(count, count + 1));
                return true;
            });
            policy.requireMetadata();
            if (expired.get() || System.nanoTime() >= deadline) throw new Fault("TIMEOUT");
            if (denied.get()) throw new Fault("OUT_OF_SCOPE");
            if (rows.size() > limit) throw new Fault("RESOURCE_LIMIT");
            if (get && params.containsKey("part")) {
                if (rows.isEmpty()) throw new Fault("NOT_FOUND");
                var row = rows.get(0);
                if (!inScope(row)) throw new Fault("OUT_OF_SCOPE");
                policy.requireRaw();
                String part = (String)params.get("part");
                var bytes = Body.bytes(row, part);
                var encoding = (String)params.getOrDefault("encoding", "utf8");
                if (encoding.equals("raw")) {
                    exported = true;
                    return new Query(new Export(bytes, part, scan, policy, api, row), Map.of());
                }
                int returned = Math.min(bytes.length(), (int)integer(params.getOrDefault("body_max_bytes", 4096L), 1, 65536));
                return new Query(Map.of("item", Body.preview(bytes, params)), Map.of("complete", true,
                        "truncated", returned < bytes.length(), "source", "proxy_history", "history_id", row.id(),
                        "representation", part.startsWith("request") ? "final_" + part : part,
                        "transformation", returned < bytes.length() ? "truncated_" + encoding : encoding,
                        "original_size_bytes", bytes.length(), "returned_bytes", returned, "encoding", encoding));
            }
            var items = new ArrayList<Map<String, Object>>(rows.size());
            for (var row : rows) {
                if (!inScope(row)) throw new Fault("OUT_OF_SCOPE");
                items.add(project(row, fields(params)));
            }
            if (get && items.isEmpty()) throw new Fault("NOT_FOUND");
            var result = get ? Map.of("item", items.get(0)) : Map.of("items", items);
            return new Query(result, Map.of("complete", true, "truncated", false,
                    "ordering", "unspecified", "selection_limit_reached", accepted.get() == limit,
                    "source", "proxy_history", "representation", "final_request", "path_excludes_query", true));
        } finally { if (!exported) scan.release(); }
    }
    public record Query(Object result, Map<String, Object> meta) {}
    public record Export(burp.api.montoya.core.ByteArray bytes, String part, Semaphore scan, Policy policy,
                         MontoyaApi api, ProxyHttpRequestResponse row) implements AutoCloseable {
        public void check() {
            policy.requireRaw();
            if (!api.scope().isInScope(row.finalRequest().url())) throw new Fault("OUT_OF_SCOPE");
        }
        @Override public void close() { scan.release(); }
    }
    private static Map<String, Object> project(ProxyHttpRequestResponse row, List<String> fields) {
        var result = new LinkedHashMap<String, Object>();
        // Resolve request metadata only when a selected field needs it.
        for (String field : fields) result.put(field, switch (field) {
            case "id" -> row.id();
            case "method" -> row.finalRequest().method();
            case "host" -> row.finalRequest().httpService().host();
            case "path" -> row.finalRequest().pathWithoutQuery();
            case "status" -> row.hasResponse() ? row.response().statusCode() : null;
            case "has_response" -> row.hasResponse();
            case "port" -> row.finalRequest().httpService().port();
            case "secure" -> row.finalRequest().httpService().secure();
            default -> throw new Fault("INVALID_ARGUMENT");
        });
        for (Object value : result.values()) if (value instanceof String text && text.length() > 8192) throw new Fault("OUTPUT_LIMIT");
        return result;
    }
}
