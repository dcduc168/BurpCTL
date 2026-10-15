package dev.burpctl.features;

import burp.api.montoya.MontoyaApi;
import dev.burpctl.ipc.Fault;
import dev.burpctl.security.Policy;
import java.awt.Component;
import java.awt.Container;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.imageio.ImageIO;
import javax.imageio.stream.MemoryCacheImageOutputStream;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

/** On-demand component rendering; no desktop capture, tab changes or retained images. */
public final class Screenshot {
    public static final int MAX_PIXELS = 4_194_304;
    public static final int MAX_PNG_BYTES = 8 * 1024 * 1024;
    private final MontoyaApi api;
    private final Policy policy;
    private final Semaphore capture = new Semaphore(1);
    public Screenshot(MontoyaApi api, Policy policy) { this.api = api; this.policy = policy; }

    public Export capture(Runnable check) {
        policy.requireScreenshot();
        if (SwingUtilities.isEventDispatchThread()) throw new Fault("FEATURE_UNAVAILABLE");
        if (!capture.tryAcquire()) throw new Fault("BUSY");
        var released = new AtomicBoolean();
        Runnable release = () -> { if (released.compareAndSet(false, true)) capture.release(); };
        var task = new FutureTask<BufferedImage>(() -> render(check));
        boolean exported = false;
        BufferedImage image = null;
        try {
            SwingUtilities.invokeLater(() -> {
                try { task.run(); }
                finally { if (task.isCancelled()) release.run(); }
            });
            try { image = task.get(2, TimeUnit.SECONDS); }
            catch (java.util.concurrent.TimeoutException e) { task.cancel(false); throw new Fault("TIMEOUT"); }
            catch (InterruptedException e) { task.cancel(false); Thread.currentThread().interrupt(); throw new Fault("TIMEOUT"); }
            catch (java.util.concurrent.ExecutionException e) {
                if (e.getCause() instanceof Fault fault) throw fault;
                throw new Fault("INTERNAL_ERROR");
            }
            check.run();
            byte[] bytes = png(image);
            check.run();
            exported = true;
            return new Export(bytes, image.getWidth(), image.getHeight(), release);
        } finally {
            if (image != null) image.flush();
            // A canceled render owns the permit until its EDT runnable finishes; never interrupt EDT.
            if (!exported && !task.isCancelled()) release.run();
        }
    }

    private BufferedImage render(Runnable check) {
        check.run();
        var frame = api.userInterface().swingUtils().suiteFrame();
        if (frame == null || !frame.isShowing() || (frame.getExtendedState() & java.awt.Frame.ICONIFIED) != 0)
            throw new Fault("FEATURE_UNAVAILABLE", "Show the main Burp window without minimizing it");
        var panes = new java.util.ArrayList<JTabbedPane>();
        int[] visited = {0};
        find(frame, panes, visited, 0);
        if (panes.size() != 1) throw new Fault("FEATURE_UNAVAILABLE", "Main Repeater pane is unavailable or ambiguous");
        var tabs = panes.get(0);
        int repeater = -1;
        for (int i = 0; i < tabs.getTabCount(); i++) {
            if (++visited[0] > 8192) throw new Fault("RESOURCE_LIMIT");
            if ("Repeater".equals(tabs.getTitleAt(i))) {
                if (repeater >= 0) throw new Fault("FEATURE_UNAVAILABLE", "Repeater pane is ambiguous");
                repeater = i;
            }
        }
        Component component = tabs.getComponentAt(repeater);
        if (!(component instanceof javax.swing.JComponent)) throw new Fault("FEATURE_UNAVAILABLE");
        int width = component.getWidth(), height = component.getHeight();
        if (width <= 0 || height <= 0) throw new Fault("FEATURE_UNAVAILABLE", "Repeater has no layout yet; open it once");
        if ((long)width * height > MAX_PIXELS) throw new Fault("RESOURCE_LIMIT", "Resize Repeater below 4194304 pixels");
        var image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        var graphics = image.createGraphics();
        try { component.printAll(graphics); check.run(); return image; }
        catch (RuntimeException e) { image.flush(); throw e; }
        finally { graphics.dispose(); }
    }

    private static void find(Component component, java.util.List<JTabbedPane> result, int[] visited, int depth) {
        if (++visited[0] > 8192 || depth > 32) throw new Fault("RESOURCE_LIMIT");
        if (!component.isVisible()) return;
        if (component instanceof JTabbedPane tabs) {
            int tools = 0;
            for (int i = 0; i < tabs.getTabCount() && tools != 7; i++) {
                if (++visited[0] > 8192) throw new Fault("RESOURCE_LIMIT");
                String title = tabs.getTitleAt(i);
                if ("Repeater".equals(title)) tools |= 1;
                if ("Proxy".equals(title)) tools |= 2;
                if ("Target".equals(title)) tools |= 4;
            }
            if (tools == 7) { result.add(tabs); return; }
        }
        if (component instanceof Container container) for (var child : container.getComponents()) find(child, result, visited, depth + 1);
    }

    private static byte[] png(BufferedImage image) {
        var output = new ByteArrayOutputStream();
        try (var stream = new MemoryCacheImageOutputStream(output) {
            @Override public void write(int value) throws IOException {
                if (getStreamPosition() >= MAX_PNG_BYTES) throw new Fault("OUTPUT_LIMIT");
                super.write(value);
            }
            @Override public void write(byte[] bytes, int offset, int length) throws IOException {
                if (length > MAX_PNG_BYTES - getStreamPosition()) throw new Fault("OUTPUT_LIMIT");
                super.write(bytes, offset, length);
            }
        }) {
            if (!ImageIO.write(image, "png", stream)) throw new Fault("FEATURE_UNAVAILABLE");
            stream.flush();
            return output.toByteArray();
        } catch (IOException e) { throw new Fault("INTERNAL_ERROR"); }
    }

    public record Export(byte[] bytes, int width, int height, Runnable release) implements AutoCloseable {
        @Override public void close() { release.run(); }
    }
}
