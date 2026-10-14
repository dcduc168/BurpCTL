import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import dev.burpctl.runtime.Server;
import dev.burpctl.security.Policy;
import java.util.List;

/** Production server with a controlled byte-read failure after the first chunk. */
public final class PartialSmokeServer {
    public static void main(String[] args) throws Exception {
        var bytes = HistorySmoke.proxy(ByteArray.class, (method, values) -> switch (method) {
            case "length" -> 131072;
            case "getByte" -> {
                if ((Integer)values[0] >= 65536) throw new IllegalStateException("Injected transfer failure");
                yield (byte)7;
            }
            default -> throw new AssertionError(method);
        });
        var request = HistorySmoke.proxy(burp.api.montoya.http.message.requests.HttpRequest.class,
                (method, values) -> switch (method) {
                    case "url" -> "http://127.0.0.1:18123/fixture/partial";
                    case "body" -> bytes;
                    default -> throw new AssertionError(method);
                });
        var row = HistorySmoke.proxy(ProxyHttpRequestResponse.class, (method, values) -> switch (method) {
            case "id" -> 102;
            case "finalRequest" -> request;
            default -> throw new AssertionError(method);
        });
        var api = HistorySmoke.proxy(MontoyaApi.class, (method, values) -> switch (method) {
            case "project" -> StatusSmoke.stub(burp.api.montoya.project.Project.class);
            case "burpSuite" -> StatusSmoke.stub(burp.api.montoya.burpsuite.BurpSuite.class);
            case "scope" -> HistorySmoke.proxy(burp.api.montoya.scope.Scope.class, (name, arguments) -> true);
            case "proxy" -> HistorySmoke.proxy(burp.api.montoya.proxy.Proxy.class, (name, arguments) -> {
                var filter = (ProxyHistoryFilter)arguments[0];
                return filter.matches(row) ? List.of(row) : List.of();
            });
            default -> throw new AssertionError(method);
        });
        var policy = new Policy(); policy.metadata.set(true); policy.raw.set(true);
        try (var server = new Server(api, policy)) {
            server.start();
            System.out.println("ready");
            System.in.read();
        }
    }
}
