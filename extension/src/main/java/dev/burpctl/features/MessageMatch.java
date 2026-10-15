package dev.burpctl.features;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import dev.burpctl.ipc.Fault;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public final class MessageMatch {
    public static byte[] needle(Map<String, Object> params) {
        History.integer(params.get("id"), 0, Integer.MAX_VALUE);
        if (!(params.get("part") instanceof String part) || !Set.of("request", "response", "request.body", "response.body").contains(part)) throw new Fault("INVALID_ARGUMENT");
        History.integer(params.getOrDefault("scan_max_bytes", 65536L), 1, 1048576);
        History.integer(params.getOrDefault("context_bytes", 0L), 0, 256);
        if (params.containsKey("text") == params.containsKey("base64")) throw new Fault("INVALID_ARGUMENT");
        Object value = params.get(params.containsKey("text") ? "text" : "base64");
        if (!(value instanceof String text) || text.length() > 8192) throw new Fault("INVALID_ARGUMENT");
        byte[] needle;
        try { needle = params.containsKey("text") ? text.getBytes(StandardCharsets.UTF_8) : Base64.getDecoder().decode(text); }
        catch (IllegalArgumentException e) { throw new Fault("INVALID_ARGUMENT"); }
        if (needle.length == 0 || needle.length > 4096) throw new Fault("INVALID_ARGUMENT");
        return needle;
    }
    static History.Query query(ProxyHttpRequestResponse row, Map<String, Object> params, byte[] needle) {
        String part = (String)params.get("part");
        var bytes = Body.bytes(row, part);
        int maximum = Math.min(bytes.length(), (int)History.integer(params.getOrDefault("scan_max_bytes", 65536L), 1, 1048576));
        int context = (int)History.integer(params.getOrDefault("context_bytes", 0L), 0, 256);
        // KMP keeps repeated-prefix patterns linear without copying the message.
        int[] fallback = new int[needle.length];
        for (int i = 1, j = 0; i < needle.length; i++) {
            while (j > 0 && needle[i] != needle[j]) j = fallback[j - 1];
            if (needle[i] == needle[j]) fallback[i] = ++j;
        }
        int offset = -1, inspected = 0;
        for (int j = 0; inspected < maximum;) {
            byte next = bytes.getByte(inspected++);
            while (j > 0 && next != needle[j]) j = fallback[j - 1];
            if (next == needle[j] && ++j == needle.length) { offset = inspected - needle.length; break; }
        }
        var result = new LinkedHashMap<String, Object>();
        result.put("matched", offset >= 0); result.put("offset", offset >= 0 ? offset : null);
        result.put("inspected_bytes", inspected); result.put("size_bytes", bytes.length());
        result.put("search_complete", offset >= 0 || inspected == bytes.length());
        if (offset >= 0 && context > 0) {
            int start = Math.max(0, offset - context), end = Math.min(maximum, offset + needle.length + context);
            // Context is capped independently of pattern length.
            end = Math.min(end, start + 512);
            byte[] snippet = new byte[end - start];
            for (int i = 0; i < snippet.length; i++) snippet[i] = bytes.getByte(start + i);
            result.put("snippet", Base64.getEncoder().encodeToString(snippet));
            result.put("snippet_offset", start); result.put("snippet_encoding", "base64");
        }
        return new History.Query(result, Map.of("source", "proxy_history", "history_id", row.id(),
                "representation", part.startsWith("request") ? "final_" + part : part,
                "transformation", "literal_byte_match", "truncated", inspected < bytes.length()));
    }
}
