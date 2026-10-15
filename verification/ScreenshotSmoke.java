import burp.api.montoya.MontoyaApi;
import dev.burpctl.features.Screenshot;
import dev.burpctl.ipc.Fault;
import dev.burpctl.security.Policy;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.*;

/** Synthetic Swing capture and production IPC fixture; sends no traffic. */
public final class ScreenshotSmoke {
    static void denied(Runnable action, String code) {
        try { action.run(); throw new AssertionError("Expected " + code); }
        catch (Fault fault) { StatusSmoke.require(fault.code.equals(code), "Wrong capture error: " + fault.code); }
    }
    public static void main(String[] args) throws Exception {
        var frame = new JFrame("BurpCTL synthetic screenshot check");
        var tabs = new JTabbedPane();
        var oversized = new java.util.concurrent.atomic.AtomicBoolean();
        var uninitialized = new java.util.concurrent.atomic.AtomicBoolean();
        var noisy = new java.util.concurrent.atomic.AtomicReference<java.awt.image.BufferedImage>();
        var pane = new JPanel() {
            @Override public int getWidth() { return uninitialized.get() ? 0 : oversized.get() ? 3000 : noisy.get() != null ? 2048 : super.getWidth(); }
            @Override public int getHeight() { return oversized.get() ? 2000 : noisy.get() != null ? 2048 : super.getHeight(); }
            @Override protected void paintComponent(java.awt.Graphics graphics) {
                StatusSmoke.require(SwingUtilities.isEventDispatchThread(), "Capture painted off EDT");
                graphics.setColor(new java.awt.Color(10, 20, 30)); graphics.fillRect(0, 0, getWidth(), getHeight());
                if (noisy.get() != null) graphics.drawImage(noisy.get(), 0, 0, null);
            }
        };
        pane.add(new JLabel("Synthetic Repeater: no real HTTP data"));
        SwingUtilities.invokeAndWait(() -> {
            tabs.addTab("Target", new JPanel()); tabs.addTab("Proxy", new JPanel()); tabs.addTab("Repeater", pane);
            tabs.setSelectedIndex(2); frame.setContentPane(tabs); frame.setSize(640, 480); frame.setVisible(true);
        });
        var uiCalls = new AtomicInteger();
        var api = HistorySmoke.proxy(MontoyaApi.class, (name, values) -> switch (name) {
            case "userInterface" -> {
                StatusSmoke.require(SwingUtilities.isEventDispatchThread(), "UI discovery off EDT"); uiCalls.incrementAndGet();
                yield HistorySmoke.proxy(burp.api.montoya.ui.UserInterface.class, (method, arguments) -> {
                    if (!method.equals("swingUtils")) throw new AssertionError(method);
                    return HistorySmoke.proxy(burp.api.montoya.ui.swing.SwingUtils.class, (call, parameters) -> {
                        if (!call.equals("suiteFrame")) throw new AssertionError(call); return frame;
                    });
                });
            }
            case "project" -> StatusSmoke.stub(burp.api.montoya.project.Project.class);
            case "burpSuite" -> StatusSmoke.stub(burp.api.montoya.burpsuite.BurpSuite.class);
            default -> throw new AssertionError("Unexpected Montoya access: " + name);
        });
        var policy = new Policy();
        try {
            if (args.length == 1 && args[0].equals("serve")) {
                policy.screenshot.set(true);
                try (var server = new dev.burpctl.runtime.Server(api, policy)) {
                    server.start(); System.out.println("ready"); System.in.read();
                }
                return;
            }
            var capture = new Screenshot(api, policy);
            denied(() -> capture.capture(policy::requireScreenshot), "PERMISSION_DENIED");
            StatusSmoke.require(uiCalls.get() == 0, "Denied capture invoked UI API");
            policy.screenshot.set(true);
            int[] visiblePixels;
            try (var image = capture.capture(policy::requireScreenshot)) {
                StatusSmoke.require(!policy.metadata.get() && !policy.raw.get(), "Capture requires history permissions");
                var decoded = javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(image.bytes()));
                StatusSmoke.require(decoded.getWidth() == image.width() && decoded.getHeight() == image.height(), "PNG dimensions");
                StatusSmoke.require((decoded.getRGB(0, 0) & 0xffffff) == 0x0a141e, "PNG pixel integrity");
                visiblePixels = decoded.getRGB(0, 0, decoded.getWidth(), decoded.getHeight(), null, 0, decoded.getWidth());
                decoded.flush();
                denied(() -> capture.capture(policy::requireScreenshot), "BUSY");
            }
            SwingUtilities.invokeAndWait(() -> tabs.setSelectedIndex(0));
            StatusSmoke.require(!pane.isShowing(), "Repeater fixture must be hidden");
            try (var image = capture.capture(policy::requireScreenshot)) {
                var decoded = javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(image.bytes()));
                StatusSmoke.require(java.util.Arrays.equals(visiblePixels,
                        decoded.getRGB(0, 0, decoded.getWidth(), decoded.getHeight(), null, 0, decoded.getWidth()))
                        && tabs.getSelectedIndex() == 0 && !pane.isShowing(), "Hidden Repeater capture changed selection or lost content");
                decoded.flush();
            }
            uninitialized.set(true);
            denied(() -> capture.capture(policy::requireScreenshot), "FEATURE_UNAVAILABLE");
            uninitialized.set(false);
            SwingUtilities.invokeAndWait(() -> { tabs.setSelectedIndex(2); oversized.set(true); });
            denied(() -> capture.capture(policy::requireScreenshot), "RESOURCE_LIMIT");
            SwingUtilities.invokeAndWait(() -> oversized.set(false));
            var noise = new java.awt.image.BufferedImage(2048, 2048, java.awt.image.BufferedImage.TYPE_INT_RGB);
            var pixels = ((java.awt.image.DataBufferInt)noise.getRaster().getDataBuffer()).getData();
            var random = new java.util.SplittableRandom(42);
            for (int i = 0; i < pixels.length; i++) pixels[i] = random.nextInt();
            SwingUtilities.invokeAndWait(() -> noisy.set(noise));
            try { denied(() -> capture.capture(policy::requireScreenshot), "OUTPUT_LIMIT"); }
            finally { SwingUtilities.invokeAndWait(() -> noisy.set(null)); noise.flush(); }
            var blocked = new java.util.concurrent.CountDownLatch(1);
            var release = new java.util.concurrent.CountDownLatch(1);
            SwingUtilities.invokeLater(() -> {
                blocked.countDown();
                try { release.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            });
            StatusSmoke.require(blocked.await(2, java.util.concurrent.TimeUnit.SECONDS), "EDT blocker did not start");
            int before = uiCalls.get();
            try {
                denied(() -> capture.capture(policy::requireScreenshot), "TIMEOUT");
                denied(() -> capture.capture(policy::requireScreenshot), "BUSY");
            } finally { release.countDown(); }
            SwingUtilities.invokeAndWait(() -> {});
            StatusSmoke.require(uiCalls.get() == before, "Canceled queued task captured later");
            try (var image = capture.capture(policy::requireScreenshot)) {
                StatusSmoke.require(image.bytes().length > 0, "Timeout retained capture permit");
            }
            System.out.println("PASS: permission before UI, EDT-only capture, PNG pixels/dimensions, hidden capture without switching tabs, independent policy, concurrency, size limits, canceled queued capture and permit cleanup");
        } finally { SwingUtilities.invokeAndWait(frame::dispose); }
    }
}
