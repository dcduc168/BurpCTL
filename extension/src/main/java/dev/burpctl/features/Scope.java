package dev.burpctl.features;

import burp.api.montoya.MontoyaApi;
import dev.burpctl.ipc.Fault;
import java.net.URI;
import java.util.Map;

public final class Scope {
    private final MontoyaApi api;
    public Scope(MontoyaApi api) { this.api = api; }
    public static String url(Object value) {
        if (!(value instanceof String url) || url.length() > 4096 || url.chars().anyMatch(ch -> ch <= 32 || ch == 127))
            throw new Fault("INVALID_ARGUMENT");
        try {
            var uri = URI.create(url);
            if (!("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
                    || uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                    || uri.getPort() < -1 || uri.getPort() == 0 || uri.getPort() > 65535) throw new Fault("INVALID_ARGUMENT");
        } catch (IllegalArgumentException e) { throw new Fault("INVALID_ARGUMENT"); }
        return url;
    }
    public Object check(Map<String, Object> params) {
        String url = url(params.get("url"));
        return Map.of("url", url, "in_scope", api.scope().isInScope(url));
    }
}
