import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.ProxyHistoryFilter;
import dev.burpctl.runtime.Server;
import dev.burpctl.security.Policy;

/** Production IPC server exposing only an in-memory synthetic corpus; sends no traffic. */
public final class HistoryServer {
    public static void main(String[] args) throws Exception {
        var rows = java.util.stream.IntStream.range(0, 100).mapToObj(id -> {
            var original = HistorySmoke.row(id);
            return HistorySmoke.proxy(ProxyHttpRequestResponse.class, (method, values) -> switch (method) {
                case "id" -> id;
                case "finalRequest" -> original.finalRequest();
                case "hasResponse" -> true;
                case "response" -> original.response();
                default -> throw new AssertionError(method);
            });
        }).toList();
        var api = HistorySmoke.proxy(MontoyaApi.class, (method, values) -> switch (method) {
            case "project" -> StatusSmoke.stub(burp.api.montoya.project.Project.class);
            case "burpSuite" -> StatusSmoke.stub(burp.api.montoya.burpsuite.BurpSuite.class);
            case "scope" -> HistorySmoke.proxy(burp.api.montoya.scope.Scope.class, (name, arguments) -> true);
            case "proxy" -> HistorySmoke.proxy(burp.api.montoya.proxy.Proxy.class, (name, arguments) -> {
                if (!name.equals("history") || arguments.length != 1) throw new AssertionError(name);
                var filter = (ProxyHistoryFilter)arguments[0];
                return rows.parallelStream().filter(filter::matches).toList();
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
