package dev.burpctl.features;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.BurpSuiteEdition;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import dev.burpctl.ipc.Fault;
import dev.burpctl.ipc.Json;
import dev.burpctl.security.Policy;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;

public final class Issues {
    private static final List<String> DEFAULT_FIELDS = List.of("id", "name", "host", "path", "severity", "confidence");
    private static final Set<String> FIELDS = Set.of("id", "name", "host", "path", "port", "secure", "severity", "confidence");
    private static final Set<String> DETAIL_FIELDS = Set.of("id", "name", "host", "path", "port", "secure", "severity", "confidence", "detail", "remediation");
    private final MontoyaApi api;
    private final Policy policy;
    private final Semaphore scan;
    public Issues(MontoyaApi api, Policy policy, Semaphore scan) { this.api = api; this.policy = policy; this.scan = scan; }
    public static void validate(Map<String, Object> params, boolean get) {
        History.fields(params, get ? List.of("id", "name", "severity", "confidence", "detail", "remediation") : DEFAULT_FIELDS, get ? DETAIL_FIELDS : FIELDS);
        if (get) {
            if (!(params.get("id") instanceof String id) || !id.matches("[0-9a-f]{64}")) throw new Fault("INVALID_ARGUMENT");
        } else {
            History.integer(params.getOrDefault("limit", 10L), 1, 100);
            if (params.containsKey("host") && (!(params.get("host") instanceof String host) || host.isEmpty() || host.length() > 1024)) throw new Fault("INVALID_ARGUMENT");
            if (params.containsKey("severity") && (!(params.get("severity") instanceof String severity) || !Set.of("high", "medium", "low", "information", "false_positive").contains(severity))) throw new Fault("INVALID_ARGUMENT");
            if (params.containsKey("confidence") && (!(params.get("confidence") instanceof String confidence) || !Set.of("certain", "firm", "tentative").contains(confidence))) throw new Fault("INVALID_ARGUMENT");
        }
    }
    private static String lower(Enum<?> value) { return value.name().toLowerCase(java.util.Locale.ROOT); }
    private static String id(AuditIssue issue) {
        try {
            var service = issue.httpService();
            var values = List.of(issue.name(), issue.baseUrl(), issue.definition().typeIndex(), issue.severity().name(), issue.confidence().name(),
                    service.host(), service.port(), service.secure());
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Json.encode(values).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) { throw new AssertionError(e); }
    }
    private Map<String, Object> project(AuditIssue issue, List<String> fields, String id) {
        var item = new LinkedHashMap<String, Object>();
        for (String field : fields) {
            Object value = switch (field) {
                case "id" -> id; case "name" -> issue.name(); case "severity" -> lower(issue.severity());
                case "confidence" -> lower(issue.confidence()); case "host" -> issue.httpService().host();
                case "port" -> issue.httpService().port(); case "secure" -> issue.httpService().secure();
                case "path" -> { String path = URI.create(issue.baseUrl()).getRawPath(); yield path.isEmpty() ? "/" : path; }
                case "detail" -> issue.detail(); case "remediation" -> issue.remediation();
                default -> throw new Fault("INVALID_ARGUMENT");
            };
            if (value instanceof String text && text.length() > (field.equals("detail") || field.equals("remediation") ? 65536 : 8192)) throw new Fault("OUTPUT_LIMIT");
            item.put(field, value);
        }
        return item;
    }
    public History.Query query(Map<String, Object> params, boolean get) {
        policy.requireIssues();
        validate(params, get);
        if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) throw new Fault("FEATURE_UNAVAILABLE");
        if (!scan.tryAcquire()) throw new Fault("BUSY");
        try {
            var fields = History.fields(params, get ? List.of("id", "name", "severity", "confidence", "detail", "remediation") : DEFAULT_FIELDS, get ? DETAIL_FIELDS : FIELDS);
            int limit = get ? 2 : (int)History.integer(params.getOrDefault("limit", 10L), 1, 100);
            var items = new ArrayList<Map<String, Object>>();
            var urls = new ArrayList<String>();
            var found = new AuditIssue[1];
            var denied = new java.util.concurrent.atomic.AtomicBoolean();
            var expired = new java.util.concurrent.atomic.AtomicBoolean();
            long deadline = System.nanoTime() + 20_000_000_000L;
            // Returning false avoids collecting a second List of matching issues.
            // node.issues() and Montoya traversal can still allocate internally.
            api.siteMap().issues(node -> {
                synchronized (items) {
                    if (System.nanoTime() >= deadline) { expired.set(true); return false; }
                    if (!policy.issues.get() || items.size() >= limit) return false;
                    for (var issue : node.issues()) {
                        if (System.nanoTime() >= deadline) { expired.set(true); break; }
                        if (!policy.issues.get() || items.size() >= limit) break;
                        String url;
                        try { url = Scope.url(issue.baseUrl()); }
                        catch (Fault e) { continue; }
                        if (!get && params.containsKey("host") && !issue.httpService().host().equalsIgnoreCase((String)params.get("host"))) continue;
                        if (!get && params.containsKey("severity") && !lower(issue.severity()).equals(params.get("severity"))) continue;
                        if (!get && params.containsKey("confidence") && !lower(issue.confidence()).equals(params.get("confidence"))) continue;
                        if (issue.name().length() > 8192 || issue.httpService().host().length() > 1024) throw new Fault("RESOURCE_LIMIT");
                        String reference = id(issue);
                        if (get && !reference.equals(params.get("id"))) continue;
                        if (!api.scope().isInScope(url)) { if (get) denied.set(true); continue; }
                        if (get && found[0] == issue) continue;
                        // Project details only after reference uniqueness has been established.
                        items.add(get ? Map.of() : project(issue, fields, reference)); urls.add(url);
                        if (get) found[0] = issue;
                    }
                }
                return false;
            });
            policy.requireIssues();
            if (expired.get() || System.nanoTime() >= deadline) throw new Fault("TIMEOUT");
            if (denied.get()) throw new Fault("OUT_OF_SCOPE");
            if (get && items.size() > 1) throw new Fault("AMBIGUOUS_REFERENCE", "Multiple findings share this metadata fingerprint; inspect them in Burp.");
            if (get && items.isEmpty()) throw new Fault("NOT_FOUND");
            for (String url : urls) if (!api.scope().isInScope(url)) throw new Fault("OUT_OF_SCOPE");
            Object result = get ? Map.of("item", project(found[0], fields, (String)params.get("id"))) : Map.of("items", items);
            policy.requireIssues();
            for (String url : urls) if (!api.scope().isInScope(url)) throw new Fault("OUT_OF_SCOPE");
            var meta = new LinkedHashMap<String, Object>(Map.of("source", "sitemap_issues", "ordering", "unspecified", "atomic_snapshot", false,
                    "selection_limit_reached", !get && items.size() == limit, "reference_kind", "metadata_sha256", "path_excludes_query", true));
            if (get) meta.put("issue_id", params.get("id"));
            return new History.Query(result, meta);
        } finally { scan.release(); }
    }
}
