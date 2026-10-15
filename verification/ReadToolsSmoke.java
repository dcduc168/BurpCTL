import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import burp.api.montoya.scanner.audit.issues.*;
import burp.api.montoya.sitemap.SiteMapNode;
import dev.burpctl.features.History;
import dev.burpctl.features.Issues;
import dev.burpctl.ipc.Fault;
import dev.burpctl.security.Policy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Focused assertions for derived reads and UI writes; no target traffic. */
public final class ReadToolsSmoke {
    static void require(boolean value, String message) { HistorySmoke.require(value, message); }
    static void fault(String code, Runnable action) {
        try { action.run(); throw new AssertionError("Expected " + code); }
        catch (Fault error) { require(error.code.equals(code), "Expected " + code + ", got " + error.code); }
    }
    static Map<?, ?> result(History.Query query) { return (Map<?, ?>)query.result(); }
    static final AtomicBoolean scoped = new AtomicBoolean(true);
    static final AtomicBoolean duplicate = new AtomicBoolean();
    static final AtomicBoolean professional = new AtomicBoolean(true);
    static final AtomicInteger historySize = new AtomicInteger(100);
    static final AtomicInteger opened = new AtomicInteger();
    static final AtomicInteger details = new AtomicInteger();
    static final AtomicInteger issueCalls = new AtomicInteger();
    static AuditIssue issue(int index) {
        return HistorySmoke.proxy(AuditIssue.class, (name, args) -> switch (name) {
            case "name" -> "Synthetic issue " + index;
            case "baseUrl" -> "http://127.0.0.1:18123/fixture/" + index + "?secret=omitted";
            case "httpService" -> HistorySmoke.row(0).finalRequest().httpService();
            case "severity" -> AuditIssueSeverity.HIGH;
            case "confidence" -> AuditIssueConfidence.FIRM;
            case "definition" -> HistorySmoke.proxy(AuditIssueDefinition.class, (method, values) -> {
                require(method.equals("typeIndex"), method); return index;
            });
            case "detail" -> { details.incrementAndGet(); yield "<p>fixture detail</p>"; }
            case "remediation" -> null;
            default -> throw new AssertionError("Implicit evidence read: " + name);
        });
    }
    static MontoyaApi api() {
        var originals = java.util.stream.IntStream.range(0, 10).mapToObj(HistorySmoke::row).toList();
        return HistorySmoke.proxy(MontoyaApi.class, (name, args) -> switch (name) {
            case "project" -> StatusSmoke.stub(burp.api.montoya.project.Project.class);
            case "burpSuite" -> HistorySmoke.proxy(burp.api.montoya.burpsuite.BurpSuite.class, (method, values) -> {
                require(method.equals("version"), method);
                return HistorySmoke.proxy(burp.api.montoya.core.Version.class, (key, arguments) -> switch (key) {
                    case "edition" -> professional.get() ? burp.api.montoya.core.BurpSuiteEdition.PROFESSIONAL : burp.api.montoya.core.BurpSuiteEdition.COMMUNITY_EDITION;
                    case "toString" -> "fixture-professional";
                    default -> throw new AssertionError(key);
                });
            });
            case "scope" -> HistorySmoke.proxy(burp.api.montoya.scope.Scope.class, (method, values) -> scoped.get());
            case "proxy" -> HistorySmoke.proxy(burp.api.montoya.proxy.Proxy.class, (method, values) -> {
                require(method.equals("history") && values.length == 1, "Filtered history required");
                return java.util.stream.IntStream.range(0, historySize.get()).parallel().mapToObj(id -> {
                    var source = originals.get(id % 10);
                    return HistorySmoke.proxy(ProxyHttpRequestResponse.class, (key, arguments) -> switch (key) {
                        case "id" -> id;
                        case "finalRequest" -> source.finalRequest();
                        case "hasResponse" -> id != 98;
                        case "response" -> source.response();
                        default -> throw new AssertionError(key);
                    });
                }).filter(((ProxyHistoryFilter)values[0])::matches).toList();
            });
            case "siteMap" -> HistorySmoke.proxy(burp.api.montoya.sitemap.SiteMap.class, (method, values) -> {
                require(method.equals("issues") && values.length == 1, "Filtered issues required"); issueCalls.incrementAndGet();
                var filter = (burp.api.montoya.sitemap.SiteMapFilter)values[0];
                var records = duplicate.get() ? List.of(issue(0), issue(0)) : List.of(issue(0), issue(1));
                var node = HistorySmoke.proxy(SiteMapNode.class, (key, arguments) -> {
                    require(key.equals("issues"), "Unexpected node message read"); return records;
                });
                require(!filter.matches(node), "Aggregation must not request an additional issues List");
                return List.of();
            });
            case "repeater" -> HistorySmoke.proxy(burp.api.montoya.repeater.Repeater.class, (method, values) -> {
                require(method.equals("sendToRepeater") && values.length == 2, "UI open only"); opened.incrementAndGet(); return null;
            });
            default -> throw new AssertionError("Unexpected side effect: " + name);
        });
    }
    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("serve")) {
            var grants = new Policy(); grants.metadata.set(true); grants.raw.set(true); grants.issues.set(true); grants.repeaterOpen.set(true);
            try (var server = new dev.burpctl.runtime.Server(api(), grants)) {
                server.start(); System.out.println("ready"); System.in.read();
            }
            return;
        }
        var policy = new Policy(); var permit = new Semaphore(1); var api = api();
        var history = new History(api, policy, permit); var issues = new Issues(api, policy, permit);
        fault("PERMISSION_DENIED", () -> history.summary(Map.of(), false));
        fault("PERMISSION_DENIED", () -> issues.query(Map.of(), false));
        policy.metadata.set(true);
        var stats = result(history.summary(Map.of("by", "method"), false));
        require(stats.get("matched").equals(100L) && stats.get("buckets").equals(Map.of("POST", 100L)), "Parallel method counts");
        stats = result(history.summary(Map.of("by", "status"), false));
        require(stats.get("buckets").equals(Map.of("200", 59L, "201", 40L, "no_response", 1L)), "Status counts and missing response");
        var query = history.summary(Map.of("limit", 10L, "fields", List.of("path", "count", "sample_id")), true);
        var endpoints = (List<?>)result(query).get("items");
        require(endpoints.size() == 10 && query.meta().get("inventory_complete").equals(true), "Exactly-at-cap inventory complete");
        require(endpoints.stream().allMatch(item -> ((Map<?, ?>)item).get("count").equals(10L)), "Dedup counts across parallel callbacks");
        require(HistorySmoke.bodies.get() == 0 && HistorySmoke.reads.get() == 0, "Summaries must not access message bytes");
        query = history.summary(Map.of("limit", 3L), true);
        require(((List<?>)result(query).get("items")).size() == 3 && query.meta().get("truncated").equals(true), "Unique cap and overflow");
        require(((List<?>)result(history.summary(Map.of("filters", Map.of("host", "missing")), true)).get("items")).isEmpty(), "Empty inventory success");
        historySize.set(20000);
        long started = System.nanoTime();
        int bodyCalls = HistorySmoke.bodies.get();
        require(result(history.summary(Map.of("by", "method"), false)).get("matched").equals(20000L), "20,000-callback aggregate count");
        var large = (List<?>)result(history.summary(Map.of("limit", 10L), true)).get("items");
        require(large.size() == 10 && large.stream().allMatch(item -> ((Map<?, ?>)item).get("count").equals(2000L)), "20,000-callback endpoint counts");
        require(HistorySmoke.bodies.get() == bodyCalls, "Large summaries never read bytes");
        System.out.printf("INFO: synthetic 20,000-row stats+endpoints %.1f ms; includes proxy fixture overhead, not a Burp benchmark%n", (System.nanoTime()-started)/1_000_000.0);
        historySize.set(100);
        fault("INVALID_ARGUMENT", () -> history.summary(Map.of("by", "path"), false));
        permit.acquireUninterruptibly();
        fault("BUSY", () -> history.summary(Map.of(), false)); permit.release();
        scoped.set(false);
        require(result(history.summary(Map.of(), false)).get("matched").equals(0L), "Scope excludes aggregates"); scoped.set(true);
        var match = Map.<String,Object>of("id", 0L, "part", "request.body", "base64", "AA==", "scan_max_bytes", 1L);
        fault("PERMISSION_DENIED", () -> history.match(match));
        policy.raw.set(true);
        byte[] payload = TrafficFixture.body(0);
        String prefix = java.util.Base64.getEncoder().encodeToString(java.util.Arrays.copyOf(payload, 5));
        query = history.match(Map.of("id", 0L, "part", "request.body", "base64", prefix, "context_bytes", 8L));
        require(result(query).get("matched").equals(true) && result(query).get("offset").equals(0), "Exact binary match");
        require(result(query).get("snippet_encoding").equals("base64"), "Bounded binary snippet");
        query = history.match(Map.of("id", 0L, "part", "request.body", "base64", prefix, "scan_max_bytes", 1L));
        require(result(query).get("matched").equals(false) && result(query).get("search_complete").equals(false), "Prefix negative is not whole-message negative");
        fault("INVALID_ARGUMENT", () -> history.match(Map.of("id", 0L, "part", "request.body", "text", "", "base64", "AA==")));
        fault("INVALID_ARGUMENT", () -> history.match(Map.of("id", 0L, "part", "request.body", "base64", "***")));
        query = history.match(Map.of("id", 0L, "part", "request.body", "text", "Việt 🦀"));
        require(result(query).get("matched").equals(true), "UTF-8 needle matches exact multibyte bytes");
        query = history.match(Map.of("id", 8L, "part", "request.body", "text", "x"));
        require(result(query).get("search_complete").equals(true) && result(query).get("matched").equals(false), "Empty message is a complete negative");
        fault("NOT_FOUND", () -> history.match(Map.of("id", 98L, "part", "response.body", "text", "x")));
        // Compare the bounded byte matcher with a simple independent oracle.
        var random = new java.util.Random(617);
        for (int sample = 0; sample < 120; sample++) {
            byte[] data = new byte[random.nextInt(100)], pattern = new byte[1 + random.nextInt(12)];
            for (int i = 0; i < data.length; i++) data[i] = (byte)random.nextInt(3);
            for (int i = 0; i < pattern.length; i++) pattern[i] = (byte)random.nextInt(3);
            int maximum = 1 + random.nextInt(100), expected = -1;
            for (int i = 0; i + pattern.length <= Math.min(maximum, data.length); i++) {
                boolean equal = true;
                for (int j = 0; j < pattern.length; j++) if (data[i+j] != pattern[j]) { equal = false; break; }
                if (equal) { expected = i; break; }
            }
            var request = HistorySmoke.proxy(burp.api.montoya.http.message.requests.HttpRequest.class, (key, values) -> switch (key) {
                case "url" -> "http://127.0.0.1:18123/test";
                case "body" -> HistorySmoke.bytes(data);
                default -> throw new AssertionError(key);
            });
            var row = HistorySmoke.proxy(ProxyHttpRequestResponse.class, (key, values) -> switch (key) {
                case "id" -> 0;
                case "finalRequest" -> request;
                default -> throw new AssertionError(key);
            });
            var testApi = HistorySmoke.proxy(MontoyaApi.class, (key, values) -> switch (key) {
                case "scope" -> HistorySmoke.proxy(burp.api.montoya.scope.Scope.class, (method, arguments) -> true);
                case "proxy" -> HistorySmoke.proxy(burp.api.montoya.proxy.Proxy.class, (method, arguments) ->
                    ((ProxyHistoryFilter)arguments[0]).matches(row) ? List.of(row) : List.of());
                default -> throw new AssertionError(key);
            });
            var observed = result(new History(testApi, policy).match(Map.of("id", 0L, "part", "request.body",
                    "base64", java.util.Base64.getEncoder().encodeToString(pattern), "scan_max_bytes", (long)maximum)));
            require(expected < 0 ? observed.get("offset") == null : observed.get("offset").equals(expected), "Randomized bounded byte-match oracle");
        }
        fault("INVALID_ARGUMENT", () -> history.match(Map.of("id", 0L, "part", "bad", "text", "x")));
        fault("PERMISSION_DENIED", () -> history.openRepeater(Map.of("id", 0L), () -> {}));
        policy.repeaterOpen.set(true);
        fault("PERMISSION_DENIED", () -> history.openRepeater(Map.of("id", 0L), () -> { throw new Fault("PERMISSION_DENIED"); }));
        require(opened.get() == 0, "Last-moment denial must precede UI mutation");
        history.openRepeater(Map.of("id", 0L, "name", "fixture"), () -> {});
        require(opened.get() == 1, "One explicit UI open, no HTTP API");
        scoped.set(false); fault("OUT_OF_SCOPE", () -> history.openRepeater(Map.of("id", 0L), () -> {})); scoped.set(true);
        policy.issues.set(true);
        query = issues.query(Map.of(), false);
        var list = (List<?>)result(query).get("items");
        String id = (String)((Map<?, ?>)list.get(0)).get("id");
        require(list.size() == 2 && details.get() == 0 && id.length() == 64, "Issue metadata without detail/message access");
        var detail = (Map<?, ?>)result(issues.query(Map.of("id", id), true)).get("item");
        require(detail.get("detail").equals("<p>fixture detail</p>") && detail.containsKey("remediation") && detail.get("remediation") == null, "Issue detail and null fidelity");
        int before = details.get(); duplicate.set(true);
        fault("AMBIGUOUS_REFERENCE", () -> issues.query(Map.of("id", id), true));
        require(details.get() == before, "No details read on ambiguous fingerprint"); duplicate.set(false);
        scoped.set(false); fault("OUT_OF_SCOPE", () -> issues.query(Map.of("id", id), true)); scoped.set(true);
        require(((List<?>)result(issues.query(Map.of("severity", "low"), false)).get("items")).isEmpty(), "Issue filtering");
        fault("INVALID_ARGUMENT", () -> issues.query(Map.of("fields", List.of("detail")), false));
        var invalid = new java.util.HashMap<String,Object>(); invalid.put("severity", null);
        fault("INVALID_ARGUMENT", () -> issues.query(invalid, false));
        invalid.clear(); invalid.put("by", null);
        fault("INVALID_ARGUMENT", () -> history.summary(invalid, false));
        before = issueCalls.get(); professional.set(false);
        fault("FEATURE_UNAVAILABLE", () -> issues.query(Map.of(), false));
        require(issueCalls.get() == before, "Edition before Site Map query"); professional.set(true);
        System.out.println("PASS: parallel stats/dedup caps/no body reads; binary prefix matching; scoped UI-open policy; issue projection, ambiguity, scope and edition");
    }
}
