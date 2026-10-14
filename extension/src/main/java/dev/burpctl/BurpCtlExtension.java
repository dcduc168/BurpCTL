package dev.burpctl;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import dev.burpctl.runtime.Server;
import dev.burpctl.security.Policy;
import javax.swing.*;

public final class BurpCtlExtension implements BurpExtension {
    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("BurpCTL 0.1.0");
        var policy = new Policy();
        var server = new Server(api, policy);
        var tab = new java.util.concurrent.atomic.AtomicReference<burp.api.montoya.core.Registration>();
        var stopped = new java.util.concurrent.atomic.AtomicBoolean();
        api.extension().registerUnloadingHandler(() -> {
            stopped.set(true); policy.metadata.set(false); policy.raw.set(false); server.close();
            var registration = tab.getAndSet(null);
            if (registration != null) registration.deregister();
        });
        SwingUtilities.invokeLater(() -> {
            if (stopped.get()) return;
            var panel = new JPanel(); panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
            var metadata = new JCheckBox("Allow CLI metadata reads for in-scope history");
            var raw = new JCheckBox("Allow CLI raw message and body reads for in-scope history");
            metadata.addActionListener(event -> {
                policy.metadata.set(metadata.isSelected());
                if (!metadata.isSelected()) { raw.setSelected(false); policy.raw.set(false); }
            });
            raw.addActionListener(event -> {
                if (!metadata.isSelected()) raw.setSelected(false);
                policy.raw.set(raw.isSelected());
            });
            panel.add(new JLabel("Enable only data you authorize local CLI tooling to read. Permissions reset on reload."));
            panel.add(metadata); panel.add(raw);
            api.userInterface().applyThemeToComponent(panel);
            var registration = api.userInterface().registerSuiteTab("BurpCTL", panel);
            tab.set(registration);
            if (stopped.get() && tab.compareAndSet(registration, null)) registration.deregister();
        });
        var startup = new Thread(() -> {
            try {
                server.start();
                if (!stopped.get()) api.logging().logToOutput("BurpCTL ready; authenticated status enabled.");
            } catch (Exception e) {
                server.close();
                if (!stopped.get()) api.logging().logToError("BurpCTL startup failed: " + e.getClass().getSimpleName() + "; check Windows runtime path and ACL support.");
            }
        }, "burpctl-start");
        startup.setDaemon(true); startup.start();
    }
}
