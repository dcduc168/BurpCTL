import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.extension.Extension;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.settings.SettingsPanel;
import dev.burpctl.BurpCtlExtension;
import dev.burpctl.ipc.Json;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import javax.swing.SwingUtilities;

/** Exercises the production entry point and unload races with synthetic Montoya APIs. */
public final class LifecycleSmoke {
    static void await(BooleanSupplier condition, String message) throws Exception {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean() && System.nanoTime() < deadline) Thread.sleep(5);
        StatusSmoke.require(condition.getAsBoolean(), message);
    }
    public static void main(String[] args) throws Exception {
        Path root = dev.burpctl.runtime.PrivateFiles.runtimeRoot().resolve("r");
        var initial = Files.exists(root) ? StatusSmoke.directories(root) : java.util.Set.<Path>of();
        var identities = new java.util.HashSet<Object>();
        for (int cycle = 0; cycle < 40; cycle++) {
            var unloading = new AtomicReference<ExtensionUnloadingHandler>();
            var panel = new AtomicReference<SettingsPanel>();
            var ready = new java.util.concurrent.atomic.AtomicBoolean();
            var registrations = new AtomicInteger();
            var deregistrations = new AtomicInteger();
            var registration = HistorySmoke.proxy(Registration.class, (name, values) -> {
                StatusSmoke.require(name.equals("deregister"), name); deregistrations.incrementAndGet(); return null;
            });
            var extension = HistorySmoke.proxy(Extension.class, (name, values) -> switch (name) {
                case "setName" -> { StatusSmoke.require("BurpCTL".equals(values[0]), "Stable extension display name"); yield null; }
                case "registerUnloadingHandler" -> { unloading.set((ExtensionUnloadingHandler)values[0]); yield registration; }
                default -> throw new AssertionError(name);
            });
            var ui = HistorySmoke.proxy(UserInterface.class, (name, values) -> switch (name) {
                case "registerSettingsPanel" -> {
                    StatusSmoke.require(SwingUtilities.isEventDispatchThread(), "Registration off EDT");
                    registrations.incrementAndGet(); panel.set((SettingsPanel)values[0]); yield registration;
                }
                case "applyThemeToComponent" -> null;
                default -> throw new AssertionError(name);
            });
            var api = HistorySmoke.proxy(MontoyaApi.class, (name, values) -> switch (name) {
                case "extension" -> extension;
                case "userInterface" -> ui;
                case "project" -> StatusSmoke.stub(burp.api.montoya.project.Project.class);
                case "burpSuite" -> StatusSmoke.stub(burp.api.montoya.burpsuite.BurpSuite.class);
                case "logging" -> HistorySmoke.proxy(burp.api.montoya.logging.Logging.class, (method, arguments) -> {
                    StatusSmoke.require(method.equals("logToOutput"), "Startup failed"); ready.set(true); return null;
                });
                default -> throw new AssertionError(name);
            });
            new BurpCtlExtension().initialize(api);
            try {
                if (cycle < 20) {
                    await(() -> panel.get() != null && ready.get(), "Settings/server not ready");
                    Path owned = null;
                    long deadline = System.nanoTime() + 5_000_000_000L;
                    while (owned == null && System.nanoTime() < deadline) {
                        if (Files.exists(root)) for (var candidate : StatusSmoke.directories(root))
                            if (!initial.contains(candidate) && Files.exists(candidate.resolve("instance.json"))) owned = candidate;
                        if (owned == null) Thread.sleep(5);
                    }
                    StatusSmoke.require(owned != null, "Server did not start");
                    var identity = Json.decode(Files.readString(owned.resolve("instance.json")));
                    StatusSmoke.require(identities.add(identity.get("instance_id")), "Reload reused instance identity");
                    var envelope = Map.of("version", Map.of("major", 1, "minor", 0), "id", "lifecycle",
                            "auth", Files.readString(owned.resolve("credential")), "method", "status", "params", Map.of(),
                            "context", Map.of("instance_id", identity.get("instance_id"), "project_id", "fixture-project"));
                    var response = StatusSmoke.request(owned.resolve("s"), envelope);
                    var permissions = (Map<?, ?>)((Map<?, ?>)response.get("result")).get("permissions");
                    StatusSmoke.require(permissions.equals(Map.of("history_metadata", false, "history_raw", false, "repeater_screenshot", false, "sitemap_issues", false, "repeater_open", false)), "Reload retained permissions");
                    var boxes = new java.util.ArrayList<javax.swing.JCheckBox>();
                    SwingUtilities.invokeAndWait(() -> {
                        SettingsSmoke.collect(panel.get().uiComponent(), boxes);
                        StatusSmoke.require(boxes.size() == 5, "Permission controls missing");
                        boxes.forEach(box -> box.doClick(0));
                    });
                    response = StatusSmoke.request(owned.resolve("s"), envelope);
                    permissions = (Map<?, ?>)((Map<?, ?>)response.get("result")).get("permissions");
                    StatusSmoke.require(permissions.equals(Map.of("history_metadata", true, "history_raw", true, "repeater_screenshot", true, "sitemap_issues", true, "repeater_open", true)), "Settings did not grant server policy");
                    await(() -> Thread.getAllStackTraces().entrySet().stream()
                            .filter(entry -> entry.getKey().getName().equals("burpctl-client"))
                            .allMatch(entry -> java.util.Arrays.stream(entry.getValue()).anyMatch(frame ->
                                    frame.getClassName().equals("java.util.concurrent.ThreadPoolExecutor") && frame.getMethodName().equals("getTask"))),
                            "Status workers did not return to idle");
                    try (var waiting = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                        waiting.connect(UnixDomainSocketAddress.of(owned.resolve("s")));
                        waiting.write(java.nio.ByteBuffer.wrap(new byte[]{0}));
                        await(() -> Thread.getAllStackTraces().entrySet().stream().anyMatch(entry ->
                                entry.getKey().getName().equals("burpctl-client") && java.util.Arrays.stream(entry.getValue())
                                        .anyMatch(frame -> frame.getClassName().equals("dev.burpctl.ipc.Frames") && frame.getMethodName().equals("transfer"))),
                                "Partial frame was not waiting in the production reader");
                        unloading.get().extensionUnloaded();
                    }
                    SwingUtilities.invokeAndWait(() -> StatusSmoke.require(boxes.stream().noneMatch(box -> box.isSelected() || box.isEnabled()), "Unload retained active UI"));
                }
            } finally { unloading.get().extensionUnloaded(); }
            SwingUtilities.invokeAndWait(() -> {});
            await(() -> Thread.getAllStackTraces().keySet().stream().noneMatch(thread -> thread.getName().startsWith("burpctl-")), "Unload retained threads");
            StatusSmoke.require(StatusSmoke.directories(root).equals(initial), "Unload retained runtime files");
            StatusSmoke.require(registrations.get() == deregistrations.get(), "Unload retained settings registration");
        }
        System.out.println("PASS: 20 initialized unload/reload cycles and 20 immediate-unload races; fresh identities, reset permissions, settings/files/threads cleanup");
    }
}
