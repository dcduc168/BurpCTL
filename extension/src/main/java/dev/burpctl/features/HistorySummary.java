package dev.burpctl.features;

import burp.api.montoya.MontoyaApi;
import dev.burpctl.ipc.Fault;
import dev.burpctl.security.Policy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.Semaphore;

/** Request-local aggregation; the predicate retains no HTTP messages. */
public final class HistorySummary {
    private static final List<String> ENDPOINT_FIELDS = List.of("method", "host", "port", "secure", "path", "count", "sample_id");
    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH");
    private record Endpoint(String method, String host, int port, boolean secure, String path) {}
    private static final class Count {
        final int sampleId;
        final String url;
        long count;
        Count(int id, String url) { sampleId = id; this.url = url; }
    }
    public static void validate(Map<String, Object> params, boolean endpoints) {
        History.validateFilters(params);
        if (endpoints) {
            History.integer(params.getOrDefault("limit", 20L), 1, 100);
            History.fields(params, ENDPOINT_FIELDS, Set.copyOf(ENDPOINT_FIELDS));
        } else if (!(params.getOrDefault("by", "status") instanceof String by) || !Set.of("status", "method").contains(by)) throw new Fault("INVALID_ARGUMENT");
    }
    static History.Query query(MontoyaApi api, Policy policy, Semaphore scan, History history, Map<String, Object> params, boolean endpoints) {
        policy.requireMetadata();
        validate(params, endpoints);
        if (!scan.tryAcquire()) throw new Fault("BUSY");
        try {
            var filters = History.filters(params);
            int limit = endpoints ? (int)History.integer(params.getOrDefault("limit", 20L), 1, 100) : 0;
            var by = params.getOrDefault("by", "status");
            var buckets = new TreeMap<String, Long>();
            var counts = new LinkedHashMap<Endpoint, Count>();
            var matched = new java.util.concurrent.atomic.AtomicLong();
            var overflow = new java.util.concurrent.atomic.AtomicBoolean();
            var expired = new java.util.concurrent.atomic.AtomicBoolean();
            long deadline = System.nanoTime() + 20_000_000_000L;
            api.proxy().history(row -> {
                if (System.nanoTime() >= deadline) { expired.set(true); return false; }
                if (!policy.metadata.get()) return false;
                try {
                    if (!history.matches(row, filters)) return false;
                    synchronized (counts) {
                        if (!endpoints) {
                            String key;
                            if (by.equals("method")) {
                                var method = row.finalRequest().method();
                                key = METHODS.contains(method) ? method : "OTHER";
                            } else {
                                int status = row.hasResponse() ? row.response().statusCode() : 0;
                                key = status == 0 ? "no_response" : status >= 100 && status <= 599 ? Integer.toString(status) : "OTHER";
                            }
                            buckets.merge(key, 1L, Long::sum);
                            matched.incrementAndGet();
                        } else {
                            var request = row.finalRequest();
                            var service = request.httpService();
                            String host = service.host().toLowerCase(java.util.Locale.ROOT);
                            String method = request.method(), path = request.pathWithoutQuery();
                            if (host.length() > 1024 || method.length() > 64 || path.length() > 8192) throw new Fault("RESOURCE_LIMIT");
                            var key = new Endpoint(method, host, service.port(), service.secure(), path);
                            var count = counts.get(key);
                            if (count == null) {
                                if (counts.size() >= limit) { overflow.set(true); return false; }
                                String url = request.url();
                                if (url.length() > 8192) throw new Fault("RESOURCE_LIMIT");
                                count = new Count(row.id(), url); counts.put(key, count);
                            }
                            count.count++;
                        }
                    }
                } catch (burp.api.montoya.http.message.requests.MalformedRequestException ignored) { }
                return false;
            });
            policy.requireMetadata();
            if (expired.get() || System.nanoTime() >= deadline) throw new Fault("TIMEOUT");
            // Scope is checked per callback; aggregate results are observations, not atomic snapshots.
            if (endpoints) for (var count : counts.values()) if (!api.scope().isInScope(count.url)) throw new Fault("OUT_OF_SCOPE");
            Map<String, Object> result;
            if (endpoints) {
                var fields = History.fields(params, ENDPOINT_FIELDS, Set.copyOf(ENDPOINT_FIELDS));
                var items = new ArrayList<Map<String, Object>>(counts.size());
                counts.forEach((key, count) -> {
                    var item = new LinkedHashMap<String, Object>();
                    for (String field : fields) item.put(field, switch (field) {
                        case "method" -> key.method(); case "host" -> key.host(); case "port" -> key.port();
                        case "secure" -> key.secure(); case "path" -> key.path(); case "count" -> count.count;
                        case "sample_id" -> count.sampleId; default -> throw new Fault("INVALID_ARGUMENT");
                    });
                    items.add(item);
                });
                result = Map.of("items", items);
            } else result = Map.of("by", by, "matched", matched.get(), "buckets", buckets);
            var meta = new LinkedHashMap<String, Object>(Map.of("complete", true, "truncated", overflow.get(),
                    "ordering", "unspecified", "atomic_snapshot", false, "source", "proxy_history"));
            if (endpoints) { meta.put("inventory_complete", !overflow.get()); meta.put("path_excludes_query", true); }
            return new History.Query(result, meta);
        } finally { scan.release(); }
    }
}
