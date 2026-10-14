package dev.burpctl.features;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import dev.burpctl.ipc.Fault;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Body {
    public static final List<String> DEFAULT_FIELDS = List.of("size_bytes", "returned_bytes", "encoding", "data", "truncated");
    public static void validate(Map<String, Object> params) {
        if (!Set.of("request", "response", "request.body", "response.body").contains(params.get("part"))) throw new Fault("INVALID_ARGUMENT");
        Object mode = params.getOrDefault("encoding", "utf8");
        if (!Set.of("utf8", "base64", "raw").contains(mode)) throw new Fault("INVALID_ARGUMENT");
        History.integer(params.getOrDefault("body_max_bytes", 4096L), 1, 65536);
        if (mode.equals("raw") && (params.containsKey("fields") || params.containsKey("body_max_bytes"))) throw new Fault("INVALID_ARGUMENT");
        fields(params);
    }
    private static List<String> fields(Map<String, Object> params) {
        Object supplied = params.getOrDefault("fields", DEFAULT_FIELDS);
        if (!(supplied instanceof List<?> fields) || fields.isEmpty() || fields.size() > DEFAULT_FIELDS.size()) throw new Fault("INVALID_ARGUMENT");
        var result = new java.util.ArrayList<String>();
        for (Object value : fields) {
            if (!(value instanceof String field) || !DEFAULT_FIELDS.contains(field) || result.contains(field)) throw new Fault("INVALID_ARGUMENT");
            result.add(field);
        }
        return result;
    }
    public static ByteArray bytes(ProxyHttpRequestResponse row, String part) {
        boolean response = part.startsWith("response");
        if (response && !row.hasResponse()) throw new Fault("NOT_FOUND");
        ByteArray bytes;
        if (response) bytes = part.endsWith(".body") ? row.response().body() : row.response().toByteArray();
        else bytes = part.endsWith(".body") ? row.finalRequest().body() : row.finalRequest().toByteArray();
        if (bytes.length() > 32 * 1024 * 1024) throw new Fault("RESOURCE_LIMIT");
        return bytes;
    }
    public static byte[] prefix(ByteArray bytes, int length) {
        var output = new byte[length];
        for (int i = 0; i < length; i++) output[i] = bytes.getByte(i);
        return output;
    }
    public static Object preview(ByteArray bytes, Map<String, Object> params) {
        int size = bytes.length();
        int length = Math.min(size, (int)History.integer(params.getOrDefault("body_max_bytes", 4096L), 1, 65536));
        var encoding = (String)params.getOrDefault("encoding", "utf8");
        var result = new LinkedHashMap<String, Object>();
        for (String field : fields(params)) result.put(field, switch (field) {
            case "size_bytes" -> size;
            case "returned_bytes" -> length;
            case "truncated" -> length < size;
            case "encoding" -> encoding;
            case "data" -> {
                byte[] prefix = prefix(bytes, length);
                if (encoding.equals("base64")) yield Base64.getEncoder().encodeToString(prefix);
                try {
                    yield StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(prefix)).toString();
                } catch (java.nio.charset.CharacterCodingException e) { throw new Fault("INVALID_ARGUMENT", "Selected prefix is not valid UTF-8; use --base64 or --raw --output."); }
            }
            default -> throw new Fault("INVALID_ARGUMENT");
        });
        return result;
    }
}
